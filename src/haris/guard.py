"""The second front door: a guard any Python agent can call in-process.

`/v1/decision` speaks `DefenseRequest`, a pydantic type the SENTINEL kit defines. That
makes a defense that is deliberately model-agnostic -- no model runs on its decision
path -- look like it only works inside one hackathon's harness. `HarisGuard` is the
adapter, not a rewrite: it normalizes an OpenAI- or Anthropic-shaped tool call (or a
plain one, or a bare final answer) into a `CandidateAction`, builds the rest of a
`DefenseRequest` from a goal, a message history and a list of context sources, and
calls the exact same `haris.engine.decide` that `/v1/decision` calls. `service.py`'s
`POST /v1/guard` is the HTTP twin of this class for callers not in Python.

Two rules this module exists to uphold, both load-bearing:

1. `check()` never raises. The simulator's fail_mode is CLOSED and this module has no
   simulator behind it to fail closed FOR -- a raising `check()` would just be a crash
   in whatever agent loop called it. So the whole body is wrapped, exactly like
   `service.py`'s `_SAFE_FALLBACK` and `defense.py`'s `HarisDefense.decide`.

2. This module never reads `run_id` or `step_id` off a contract object. It CONSTRUCTS
   `DefenseRequest`, so a `run_id`/`step_id` value only ever appears here as a
   constructor keyword argument (an `ast.keyword`, not an `ast.Attribute`) -- never as
   `request.run_id`. `tests/test_no_hardcoding.py`'s label-field audit exempts
   `recall.py` for `run_id` alone, on the argument that a partition key an opaque
   dictionary is keyed by is not the same thing as a scenario label reaching a decision
   as content; this module gets no such exemption and needs none, because it never
   attributes-reads either field in the first place. Keep it that way: if a future edit
   here ever writes `.run_id` or `.step_id` on anything, that is the bug this docstring
   is warning about, not a false positive in the audit.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.defenses.interface import ConversationItem, DefenseRequest, HistoryDigest, ProvenanceRecord

from haris import engine
from haris.config import SETTINGS, Settings

# --- Public shapes -------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """A piece of context the agent saw, and where it came from."""

    text: str
    trust: str = "untrusted_external"
    sensitivity: str = "internal"
    id: str | None = None


@dataclass(frozen=True)
class Verdict:
    decision: str
    risk: float
    confidence: float
    reason_codes: list[str]
    explanation: str
    rewritten: dict | None
    metadata: dict


def _escalate_fallback() -> Verdict:
    """The same posture as `service.py`'s `_SAFE_FALLBACK`, for the same reason: this is
    the answer a caller gets when something inside `check` went wrong in a way we did
    not anticipate. A fresh instance every call -- `Verdict` is frozen but its list and
    dict fields are not, and handing every caller the SAME list object would let one
    caller's accidental mutation corrupt what the next caller sees.
    """
    return Verdict(
        decision="escalate",
        risk=0.5,
        confidence=0.0,
        reason_codes=["HARIS_INTERNAL_ERROR"],
        explanation="HARIS could not evaluate this action; deferring to a human.",
        rewritten=None,
        metadata={},
    )


# --- Trust / sensitivity parsing ------------------------------------------------------------

# "Absence of evidence is not evidence of trust" (haris/trust.py). A caller's `Source` or
# message can name a trust or sensitivity level we do not recognize -- a typo, a future
# kit value, a caller that made one up -- and the only safe reading is the one that grants
# nothing: least trusted, most sensitive. Silently defaulting the other way (most trusted,
# least sensitive) is exactly how an unrecognized level would launder authority.


def _trust_level(value: str) -> TrustLevel:
    try:
        return TrustLevel(value)
    except ValueError:
        return TrustLevel.ADVERSARY_CONTROLLED


def _sensitivity(value: str) -> Sensitivity:
    try:
        return Sensitivity(value)
    except ValueError:
        return Sensitivity.RESTRICTED


# --- Message roles ---------------------------------------------------------------------------

# ConversationItem.role is a fixed contract enum (user|agent|tool|memory|safety|human); it
# is a category label, not a trust judgement. Trust comes only from the Provenance each
# item points to, via the mapping below.
_CONVERSATION_ROLE_BY_MESSAGE_ROLE: dict[str, str] = {
    "system": "safety",
    "user": "user",
    "assistant": "agent",
    "tool": "tool",
    "function": "tool",
}

_TRUST_BY_MESSAGE_ROLE: dict[str, TrustLevel] = {
    "system": TrustLevel.SYSTEM_POLICY,
    "user": TrustLevel.AUTHENTICATED_USER,
    "assistant": TrustLevel.TRUSTED_INTERNAL,
    # A tool result is data the agent fetched, not something the authenticated user
    # said -- and planting an instruction inside the content a tool call returns, for
    # the agent to read back out and obey, is a named attack family in the benchmark
    # this defense is scored against. This default is the load-bearing choice here.
    "tool": TrustLevel.UNTRUSTED_EXTERNAL,
    "function": TrustLevel.UNTRUSTED_EXTERNAL,
}

_SOURCE_TYPE_BY_MESSAGE_ROLE: dict[str, SourceType] = {
    "system": SourceType.SYSTEM,
    "user": SourceType.USER,
    "tool": SourceType.TOOL_OUTPUT,
    "function": SourceType.TOOL_OUTPUT,
}

_GUARD_ACTOR = "haris.guard"
_MESSAGES_RETRIEVAL = "guard.messages"
_SOURCES_RETRIEVAL = "guard.sources"


def _message_text(content: Any) -> str:
    """`content` is either a string or a list of blocks each having `text` or `content`
    (task-2-brief.md) -- the two shapes OpenAI's and Anthropic's content-block arrays use.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if not isinstance(block, Mapping):
                continue
            text = block.get("text", block.get("content"))
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(parts)
    return ""


def _build_messages(
    messages: Sequence[Any], now: datetime
) -> tuple[list[ProvenanceRecord], list[ConversationItem]]:
    records: list[ProvenanceRecord] = []
    items: list[ConversationItem] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            # A malformed entry contributes no evidence rather than aborting the whole
            # request -- the same posture as an unrecognized trust string.
            continue
        role = str(message.get("role", "")).lower()
        content = _message_text(message.get("content"))
        pid = f"guard-message-{index}"
        provenance = Provenance(
            source_type=_SOURCE_TYPE_BY_MESSAGE_ROLE.get(role, SourceType.DOCUMENT),
            source_id=pid,
            trust_level=_TRUST_BY_MESSAGE_ROLE.get(role, TrustLevel.ADVERSARY_CONTROLLED),
            origin_actor=_GUARD_ACTOR,
            retrieved_via=_MESSAGES_RETRIEVAL,
            sensitivity=Sensitivity.INTERNAL,
            timestamp=now,
        )
        records.append(ProvenanceRecord(id=pid, provenance=provenance))
        items.append(
            ConversationItem(
                role=_CONVERSATION_ROLE_BY_MESSAGE_ROLE.get(role, "tool"),
                kind="message",
                content=content,
                provenance_ids=[pid],
            )
        )
    return records, items


def _coerce_source(item: Source | Mapping[str, Any]) -> Source | None:
    if isinstance(item, Source):
        return item
    if isinstance(item, Mapping):
        return Source(
            text=str(item.get("text", "")),
            trust=str(item.get("trust", "untrusted_external")),
            sensitivity=str(item.get("sensitivity", "internal")),
            id=item.get("id"),
        )
    return None


def _build_sources(
    sources: Sequence[Source | Mapping[str, Any]], now: datetime
) -> tuple[list[ProvenanceRecord], list[ConversationItem]]:
    """Sources become ProvenanceRecords at their declared trust and sensitivity, and
    conversation items referencing them (task-2-brief.md). `SourceType.DOCUMENT` is the
    contract's own generic bucket -- a `Source` carries no domain-specific kind, and
    inventing one from its text would be exactly the keyword-matching hard rule 1 forbids.
    """
    records: list[ProvenanceRecord] = []
    items: list[ConversationItem] = []
    for index, raw in enumerate(sources):
        source = _coerce_source(raw)
        if source is None:
            continue
        pid = source.id or f"guard-source-{index}"
        provenance = Provenance(
            source_type=SourceType.DOCUMENT,
            source_id=pid,
            trust_level=_trust_level(source.trust),
            origin_actor=_GUARD_ACTOR,
            retrieved_via=_SOURCES_RETRIEVAL,
            sensitivity=_sensitivity(source.sensitivity),
            timestamp=now,
        )
        records.append(ProvenanceRecord(id=pid, provenance=provenance))
        items.append(ConversationItem(role="tool", kind="source", content=source.text, provenance_ids=[pid]))
    return records, items


# --- proposed action normalization ------------------------------------------------------------


class _Shape(Enum):
    """Which of the four accepted `proposed` shapes we saw, so a `rewrite` can be handed
    back in the same shape it arrived in (task-2-brief.md) instead of a shape the caller
    now has to translate before it can feed it back to its own provider.
    """

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    PLAIN = "plain"
    FINAL_STR = "final_str"
    FINAL_MESSAGE = "final_message"


# CandidateAction.tool must match ^[a-z][a-z0-9_]{1,63}$ and .arguments keys must be valid
# Python identifiers of at most 64 characters (sentinel.core.actions). Real tool names from
# OpenAI/Anthropic callers normally satisfy this already; these two sanitizers exist so a
# tool name or argument key that does not still produces a judgeable action instead of a
# pydantic ValidationError that would otherwise only be caught by check()'s outer fallback
# -- which would mean an ordinary, non-malicious call getting HARIS_INTERNAL_ERROR instead
# of an actual decision.
_INVALID_TOOL_CHARS = re.compile(r"[^a-z0-9_]")
_INVALID_KEY_CHARS = re.compile(r"[^0-9A-Za-z_]")
MAX_ARGUMENTS = 32


def _safe_tool_name(name: str) -> str:
    lowered = _INVALID_TOOL_CHARS.sub("_", name.lower()).strip("_")
    if not lowered or not lowered[0].isalpha():
        lowered = f"tool_{lowered}" if lowered else "tool"
    lowered = lowered[:64]
    if len(lowered) < 2:
        lowered = (lowered + "_x")[:64]
    return lowered


def _safe_arg_key(key: str) -> str:
    candidate = _INVALID_KEY_CHARS.sub("_", str(key))
    if not candidate or candidate[0].isdigit():
        candidate = f"_{candidate}"
    return candidate[:64]


def _flatten_arguments(raw: Mapping[str, Any]) -> dict[str, Any]:
    """`CandidateAction.arguments` only accepts flat `str | int | float | bool | None`
    values. An OpenAI/Anthropic tool call can carry a nested object or array as an
    argument value; rather than raise (or silently drop it), fold it to its JSON text --
    it stays visible to taint/redaction scanning (both run on stringified arguments) and
    round-trips back out through `_render_rewritten` unless a rewrite touched it.
    """
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[_safe_arg_key(key)] = value
        else:
            try:
                out[_safe_arg_key(key)] = json.dumps(value, sort_keys=True)
            except TypeError:
                out[_safe_arg_key(key)] = str(value)
        if len(out) >= MAX_ARGUMENTS:
            break
    return out


def _parse_openai_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        # OpenAI's `function.arguments` is a JSON string the model produced; a truncated
        # or hand-edited one is real traffic, not an attack. Keeping it as a single
        # string argument (task-2-brief.md) is how the call stays judgeable instead of
        # falling back to the internal-error escalation for an ordinary parse hiccup.
        return {"value": raw}
    return dict(parsed) if isinstance(parsed, Mapping) else {"value": raw}


def _tool_call_action(tool_name: str, raw_arguments: Mapping[str, Any]) -> CandidateAction:
    return CandidateAction(
        type=ActionType.TOOL_CALL,
        tool=_safe_tool_name(tool_name),
        arguments=_flatten_arguments(raw_arguments),
    )


def _normalize_proposed(proposed: Any) -> tuple[CandidateAction, _Shape, dict[str, Any]]:
    if isinstance(proposed, Mapping):
        function = proposed.get("function")
        if isinstance(function, Mapping) and isinstance(function.get("name"), str):
            envelope = {k: v for k, v in proposed.items() if k != "function"}
            arguments = _parse_openai_arguments(function.get("arguments"))
            return _tool_call_action(function["name"], arguments), _Shape.OPENAI, envelope

        if proposed.get("type") == "tool_use" and isinstance(proposed.get("name"), str):
            envelope = {k: v for k, v in proposed.items() if k not in ("name", "input")}
            raw_input = proposed.get("input")
            arguments = raw_input if isinstance(raw_input, Mapping) else {}
            return _tool_call_action(proposed["name"], arguments), _Shape.ANTHROPIC, envelope

        if isinstance(proposed.get("name"), str) and "content" not in proposed:
            envelope = {k: v for k, v in proposed.items() if k not in ("name", "arguments")}
            raw_arguments = proposed.get("arguments")
            arguments = raw_arguments if isinstance(raw_arguments, Mapping) else {}
            return _tool_call_action(proposed["name"], arguments), _Shape.PLAIN, envelope

        # Nothing tool-call-shaped matched: whatever this is, it reads as the agent's
        # final answer rather than a call it wants judged before it takes effect.
        content = proposed.get("content")
        if not isinstance(content, str):
            content = "" if content is None else str(content)
        envelope = {k: v for k, v in proposed.items() if k != "content"}
        return CandidateAction(type=ActionType.RESPOND, content=content, final=True), _Shape.FINAL_MESSAGE, envelope

    if isinstance(proposed, str):
        return CandidateAction(type=ActionType.RESPOND, content=proposed, final=True), _Shape.FINAL_STR, {}

    # Not a mapping, not a string: not a shape this adapter documents. str()-ing it into
    # a final response keeps `check` judgeable; the outer try/except in `check` is the
    # last line of defense against a bad `proposed`, not the first.
    content = str(proposed)[:16_000]
    return CandidateAction(type=ActionType.RESPOND, content=content, final=True), _Shape.FINAL_STR, {}


def _render_rewritten(shape: _Shape, envelope: dict[str, Any], action: CandidateAction) -> dict[str, Any] | None:
    """`rewritten` comes back in the caller's own shape (task-2-brief.md): OpenAI in,
    OpenAI out with `arguments` re-serialized to a JSON string; Anthropic in, Anthropic
    out with `input` as a dict (Anthropic never stringifies it); plain in, plain out. A
    final answer always renders as `{"content": ...}` (plus whatever envelope it carried,
    e.g. `role`) so `Verdict.rewritten` stays `dict | None` for every shape, matching its
    declared type rather than returning a bare string for the two final-answer shapes.
    """
    if shape is _Shape.OPENAI:
        return {**envelope, "function": {"name": action.tool, "arguments": json.dumps(dict(action.arguments))}}
    if shape is _Shape.ANTHROPIC:
        return {**envelope, "name": action.tool, "input": dict(action.arguments)}
    if shape is _Shape.PLAIN:
        return {**envelope, "name": action.tool, "arguments": dict(action.arguments)}
    if shape in (_Shape.FINAL_STR, _Shape.FINAL_MESSAGE):
        return {**envelope, "content": action.content}
    return None


def _default_run_id(goal: str) -> str:
    """A stable value derived from the goal, so a caller looping through several steps of
    the same task without ever naming a run still gets haris/recall.py's cross-call taint
    memory instead of silently restarting it every call -- the exact failure mode
    report.md 8.1 documents for the kit itself. A caller driving several independent
    conversations from the same (or template-identical) goal text must pass its own
    `run_id`, or those conversations will share one taint memory that does not belong to
    either of them.
    """
    digest = hashlib.sha256(goal.encode("utf-8")).hexdigest()[:24]
    return f"guard-{digest}"


class HarisGuard:
    """The in-process front door. One instance per fixed policy; call `check()` per action."""

    def __init__(
        self,
        *,
        allowed_tools: Sequence[str] | None = None,
        consequential_tools: Sequence[str] | None = None,
        confirmation_required_tools: Sequence[str] | None = None,
        internal_email_domains: Sequence[str] | None = None,
        rules: Sequence[dict] | None = None,
        policy_id: str = "haris.guard",
        settings: Settings = SETTINGS,
    ) -> None:
        self._policy_context: dict[str, Any] = {
            "policy_id": policy_id,
            "allowed_tools": list(allowed_tools) if allowed_tools is not None else [],
            "consequential_tools": list(consequential_tools) if consequential_tools is not None else [],
            "confirmation_required_tools": (
                list(confirmation_required_tools) if confirmation_required_tools is not None else []
            ),
            "internal_email_domains": list(internal_email_domains) if internal_email_domains is not None else [],
            "rules": list(rules) if rules is not None else [],
        }
        self._settings = settings
        # `step_id` defaults to a per-instance counter (task-2-brief.md). Named
        # `_step_counter`, not `_step_id`/`step_id`: this file's own docstring explains
        # why no attribute here may be named exactly `run_id` or `step_id`.
        self._step_counter = 0
        self._step_lock = threading.Lock()

    def _next_step(self) -> int:
        with self._step_lock:
            value = self._step_counter
            self._step_counter += 1
            return value

    def check(
        self,
        *,
        goal: str,
        proposed: Any,
        messages: Sequence[Any] = (),
        sources: Sequence[Source | dict] = (),
        run_id: str | None = None,
        step_id: int | None = None,
        confirmations: Sequence[str] = (),
    ) -> Verdict:
        try:
            return self._check(
                goal=goal,
                proposed=proposed,
                messages=messages,
                sources=sources,
                run_id=run_id,
                step_id=step_id,
                confirmations=confirmations,
            )
        except Exception:  # noqa: BLE001 -- a decision path must degrade, never raise
            return _escalate_fallback()

    def _check(
        self,
        *,
        goal: str,
        proposed: Any,
        messages: Sequence[Any],
        sources: Sequence[Source | dict],
        run_id: str | None,
        step_id: int | None,
        confirmations: Sequence[str],
    ) -> Verdict:
        resolved_run_id = run_id if run_id else _default_run_id(goal)
        resolved_step_id = step_id if step_id is not None else self._next_step()

        action, shape, envelope = _normalize_proposed(proposed)

        now = datetime.now(timezone.utc)
        message_records, message_items = _build_messages(messages, now)
        source_records, source_items = _build_sources(sources, now)

        request = DefenseRequest(
            run_id=resolved_run_id,
            step_id=resolved_step_id,
            user_goal=goal,
            conversation=[*message_items, *source_items],
            observation=None,
            candidate_action=action,
            policy_context=self._policy_context,
            provenance=[*message_records, *source_records],
            history_digest=HistoryDigest(confirmations_granted=list(confirmations)),
        )

        # Via the module, not a bound name imported at load time: this is what lets a
        # caller (see tests/test_guard.py) monkeypatch `haris.engine.decide` and have it
        # take effect here, the same way it would for `haris.defense.HarisDefense`.
        decision = engine.decide(request, self._settings)

        rewritten = None
        if decision.decision is Decision.REWRITE and decision.rewritten_action is not None:
            rewritten = _render_rewritten(shape, envelope, decision.rewritten_action)

        return Verdict(
            decision=decision.decision.value,
            risk=decision.risk_score,
            confidence=decision.confidence,
            reason_codes=list(decision.reason_codes),
            explanation=decision.explanation or "",
            rewritten=rewritten,
            metadata=dict(decision.metadata),
        )
