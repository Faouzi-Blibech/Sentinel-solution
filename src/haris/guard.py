"""The second front door: a guard any Python agent can call in-process.

`/v1/decision` speaks `DefenseRequest`, a pydantic type the SENTINEL kit defines. That
makes a defense that is deliberately model-agnostic -- no model runs on its decision
path -- look like it only works inside one hackathon's harness. `HarisGuard` is the
adapter, not a rewrite: it normalizes an OpenAI- or Anthropic-shaped tool call (or a
plain one, or a bare final answer) into a `CandidateAction`, builds the rest of a
`DefenseRequest` from a goal, a message history and a list of context sources, and
calls the exact same `haris.engine.decide` that `/v1/decision` calls. `service.py`'s
`POST /v1/guard` is the HTTP twin of this class for callers not in Python.

Rules this module exists to uphold, all load-bearing:

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
   attribute-reads either field in the first place. Keep it that way: if a future edit
   here ever writes `.run_id` or `.step_id` on anything, that is the bug this docstring
   is warning about, not a false positive in the audit.

3. An input this module cannot confidently normalize or faithfully represent never
   defaults to "harmless final answer" or "silently drop the part that didn't fit" --
   both are fail-opens. It escalates instead, with a `GUARD_*` reason code that says
   what happened, distinct from `HARIS_INTERNAL_ERROR` (which means something actually
   broke, not "your input was unusual"). See `_GuardEscalate` and its raise sites.

4. `run_id` has no goal-derived default. Each `HarisGuard` instance gets one random
   default generated once at construction (`uuid4`), so calls through the SAME instance
   share `haris/recall.py`'s cross-call taint memory with each other, but two different
   instances -- e.g. two different HTTP requests through `/v1/guard`, which builds a
   fresh `HarisGuard` per request -- never do. A goal-derived default was tried first
   and rejected: two unrelated callers who happened to share boilerplate goal text (or
   one caller whose goal text drifts turn to turn) would otherwise share, or lose, a
   taint bucket that was never theirs to share or lose. `decide()` is invariant under
   any bijective relabelling of `run_id` -- the same argument that justifies
   `recall.py`'s audit exemption -- so this changes nothing about how any single verdict
   is computed, only which calls share memory with which.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sentinel.core.actions import MAX_ARG_CHARS, MAX_CONTENT_CHARS, ActionType, CandidateAction, Decision
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
    # The exact digest `haris/lifecycle.py::assess_confirmation` matches against
    # `history_digest.confirmations_granted`. A caller cannot compute this themselves
    # without importing the kit and reproducing CandidateAction's private
    # canonicalization -- so a confirmation-gated tool could never actually be
    # confirmed through this adapter without it. Echo it back in a later `check()`
    # call's `confirmations` to approve this exact action. `None` when no action was
    # successfully normalized (an escalate over shape/representability problems).
    action_digest: str | None = None


# --- Guard-level reason codes ---------------------------------------------------------------

# Distinct from anything `haris/signals.py` emits: these describe a problem with the
# ADAPTER's ability to represent or recognize `proposed`, not a risk signal the decision
# core found in a successfully-built action. Keeping them visually distinct (a `GUARD_`
# prefix) lets an observer reading `reason_codes` tell "the core judged this and did not
# like it" apart from "the adapter could not confidently hand the core anything to judge
# at all" -- collapsing both into HARIS_INTERNAL_ERROR was the fail-open this file used
# to have: an unrecognized shape read as "nothing wrong here", not as a fault.
GUARD_UNRECOGNIZED_ACTION_SHAPE = "GUARD_UNRECOGNIZED_ACTION_SHAPE"
GUARD_MULTIPLE_TOOL_CALLS = "GUARD_MULTIPLE_TOOL_CALLS"
GUARD_ACTION_NOT_REPRESENTABLE = "GUARD_ACTION_NOT_REPRESENTABLE"
GUARD_VALUE_TOO_LONG = "GUARD_VALUE_TOO_LONG"
GUARD_REWRITE_TOOL_UNDECLARED = "GUARD_REWRITE_TOOL_UNDECLARED"
HARIS_INTERNAL_ERROR = "HARIS_INTERNAL_ERROR"


class _GuardEscalate(Exception):
    """Raised internally to short-circuit straight to an escalate Verdict with a
    specific reason code, from deep inside normalization where threading a return value
    back through every caller would be worse than an exception. Always caught close to
    where `_normalize_proposed` is called -- never allowed to reach `check()`'s own
    generic `except Exception`, which exists for genuinely unanticipated failures and
    would collapse this back into the uninformative HARIS_INTERNAL_ERROR this class
    exists to avoid.
    """

    def __init__(self, reason_code: str, explanation: str) -> None:
        super().__init__(explanation)
        self.reason_code = reason_code
        self.explanation = explanation[:500]


def _guard_escalate(reason_code: str, explanation: str) -> Verdict:
    """The shared shape for every guard-level escalate: input the adapter could not
    confidently judge. A fresh `Verdict` every call -- it is frozen but its list/dict
    fields are not, and handing every caller the SAME list object would let one
    caller's accidental mutation corrupt what the next caller sees.
    """
    return Verdict(
        decision="escalate",
        risk=0.5,
        confidence=0.0,
        reason_codes=[reason_code],
        explanation=explanation[:500],
        rewritten=None,
        metadata={},
        action_digest=None,
    )


def _escalate_fallback() -> Verdict:
    """The same posture as `service.py`'s `_SAFE_FALLBACK`: the answer a caller gets
    when something inside `check` broke in a way this module did not anticipate.
    Deliberately context-free (unlike `_guard_escalate`'s other callers, which each
    explain what went wrong) -- by the time this fires, the failure could be anything.
    """
    return _guard_escalate(
        HARIS_INTERNAL_ERROR, "HARIS could not evaluate this action; deferring to a human."
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


def _tool_result_text(block: Mapping[str, Any]) -> str:
    """A `tool_result` block's own `content` is either a string or a nested list of
    blocks (Anthropic's two documented shapes for it) -- recurse exactly the way
    `_message_text` does for a top-level message, so a directive buried two levels deep
    (tool_result -> block -> text) is not silently dropped from provenance.
    """
    return _message_text(block.get("content"))


def _split_message_content(content: Any) -> tuple[str, list[str]]:
    """Returns (ordinary_text, tool_result_texts).

    Anthropic has no `tool` role: a tool result arrives as an ordinary `role: "user"`
    message whose `content` list happens to hold a `tool_result` block. Reading that
    block at the enclosing role's trust (`user` -> authenticated_user) is exactly the
    laundering this whole defense exists to prevent -- a tool result is data the agent
    fetched, regardless of which role's turn happened to carry it back. Splitting here,
    before any trust is assigned, is what stops it: every `tool_result` block becomes
    its own conversation item at `untrusted_external`, independent of the message's own
    role, and everything else in the message keeps that role's own trust.
    """
    if isinstance(content, str):
        return content, []
    if not isinstance(content, list):
        return "", []
    ordinary_blocks: list[Any] = []
    tool_results: list[str] = []
    for block in content:
        if not isinstance(block, Mapping):
            continue
        if block.get("type") == "tool_result":
            tool_results.append(_tool_result_text(block))
        else:
            ordinary_blocks.append(block)
    return _message_text(ordinary_blocks), tool_results


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
        ordinary_text, tool_result_texts = _split_message_content(message.get("content"))

        if ordinary_text:
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
                    content=ordinary_text,
                    provenance_ids=[pid],
                )
            )

        for block_index, text in enumerate(tool_result_texts):
            if not text:
                continue
            pid = f"guard-message-{index}-tool-result-{block_index}"
            provenance = Provenance(
                source_type=SourceType.TOOL_OUTPUT,
                source_id=pid,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                origin_actor=_GUARD_ACTOR,
                retrieved_via=_MESSAGES_RETRIEVAL,
                sensitivity=Sensitivity.INTERNAL,
                timestamp=now,
            )
            records.append(ProvenanceRecord(id=pid, provenance=provenance))
            items.append(ConversationItem(role="tool", kind="tool_result", content=text, provenance_ids=[pid]))
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
        # The record id `TrustView` keys provenance lookups by is ALWAYS ours, never the
        # caller's: a caller-supplied `id` that happened to collide with an id this
        # module generates elsewhere (e.g. `guard-message-1`) would re-label that other
        # item's trust -- a caller-controlled way to launder trust. The caller's own id,
        # if given, is preserved as plain metadata on `source_id` instead, capped to the
        # contract's 128-char field limit (safe to truncate: it is a label, never
        # content the taint/leak scan reads).
        pid = f"guard-source-{index}"
        caller_id = (source.id or pid)[:128] or pid
        provenance = Provenance(
            source_type=SourceType.DOCUMENT,
            source_id=caller_id,
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


@dataclass(frozen=True)
class _Naming:
    """What `_normalize_proposed` sanitized away, kept so a rewrite can be rendered back
    in the caller's OWN vocabulary instead of this module's internal snake_case (I4:
    "restore the caller's original tool and key names").
    """

    original_tool: str | None
    key_by_sanitized: dict[str, str]


_EMPTY_NAMING = _Naming(original_tool=None, key_by_sanitized={})


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

# Mirrors haris/dataflow.py's _DESTINATION_KEYS and haris/rewrite.py's ROUTING_KEYS (those
# two already keep each other in sync per rewrite.py's own comment; this is the same set
# again, for the same reason -- see _stringify_argument below).
_DESTINATION_KEYS = frozenset({"to", "recipient", "destination", "url", "endpoint", "address", "email"})


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


def _stringify_argument(key: str, value: Any) -> Any:
    """Fold one raw argument value into the flat str|int|float|bool|None
    `CandidateAction.arguments` requires.

    A routing argument (`to`, `recipient`, ...) that arrives as a list of address
    strings -- ordinary for a multi-recipient send -- gets a plain comma-join instead of
    the generic JSON-bracket encoding below: `haris/dataflow.py`'s internal-domain check
    is a string SUFFIX match, and `["a@corp.example"]` does not end in `@corp.example`
    the way `a@corp.example` does, so a single-recipient internal list would otherwise
    misread as an external destination. A joined list of several recipients is read
    address by address by `dataflow._recipients`, so it is internal exactly when every
    recipient is.
    """
    if key.lower() in _DESTINATION_KEYS and isinstance(value, list) and value and all(
        isinstance(v, str) for v in value
    ):
        return ", ".join(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def _flatten_arguments(raw: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Sanitize `raw` into `CandidateAction.arguments`' flat shape, returning
    (arguments, key_by_sanitized) -- the reverse key mapping `_render_rewritten` uses to
    hand a caller their own key spelling back.

    Any step that cannot be done faithfully escalates instead of doing it lossily (I2):
    more than 32 arguments (dropping the rest would judge a different action than the
    one that runs), two distinct keys sanitizing to the same identifier (whichever won
    would silently discard the other, possibly the one carrying a secret), or a value
    over the contract's per-argument length cap (truncating could hide a secret in the
    cut tail -- see MAX_ARG_CHARS below).
    """
    if len(raw) > MAX_ARGUMENTS:
        raise _GuardEscalate(
            GUARD_ACTION_NOT_REPRESENTABLE,
            f"{len(raw)} arguments exceed the contract's {MAX_ARGUMENTS}-argument limit; "
            "dropping any of them would judge a different action than the one that runs.",
        )

    out: dict[str, Any] = {}
    key_by_sanitized: dict[str, str] = {}
    for key, value in raw.items():
        safe_key = _safe_arg_key(key)
        collision = key_by_sanitized.get(safe_key)
        if collision is not None and collision != key:
            raise _GuardEscalate(
                GUARD_ACTION_NOT_REPRESENTABLE,
                f"argument keys {collision!r} and {key!r} both sanitize to {safe_key!r}; "
                "cannot represent this action faithfully.",
            )
        key_by_sanitized[safe_key] = key

        rendered = _stringify_argument(key, value)
        if isinstance(rendered, str) and len(rendered) > MAX_ARG_CHARS:
            raise _GuardEscalate(
                GUARD_VALUE_TOO_LONG,
                f"argument {key!r} is {len(rendered)} chars, over the contract's "
                f"{MAX_ARG_CHARS}-char limit; truncating could hide a secret in the cut "
                "tail, so this escalates instead of silently shortening it.",
            )
        out[safe_key] = rendered
    return out, key_by_sanitized


def _check_content_length(content: str) -> None:
    if len(content) > MAX_CONTENT_CHARS:
        raise _GuardEscalate(
            GUARD_VALUE_TOO_LONG,
            f"final answer is {len(content)} chars, over the contract's "
            f"{MAX_CONTENT_CHARS}-char limit; truncating could hide a secret in the cut "
            "tail, so this escalates instead of silently shortening it.",
        )


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


def _coerce_plain_arguments(raw: Any) -> dict[str, Any]:
    """The plain `{"name", "arguments"}` shape usually carries `arguments` as a real
    dict, but the OpenAI Responses API's `function_call` item shape matches "plain"
    (has `name`, no `content`) while still carrying `arguments` as a JSON STRING, same
    as the chat-completions `function` wrapper does. Without this, that item's
    arguments silently became `{}` -- a restricted value in a dropped argument reads as
    a clean call (C2). Any string value gets the same lenient JSON-or-keep-as-is
    treatment `_parse_openai_arguments` gives the chat-completions shape.
    """
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str):
        return _parse_openai_arguments(raw)
    return {}


def _tool_call_action(tool_name: str, raw_arguments: Mapping[str, Any]) -> tuple[CandidateAction, _Naming]:
    arguments, key_by_sanitized = _flatten_arguments(raw_arguments)
    action = CandidateAction(type=ActionType.TOOL_CALL, tool=_safe_tool_name(tool_name), arguments=arguments)
    return action, _Naming(original_tool=tool_name, key_by_sanitized=key_by_sanitized)


# --- Reading a value from either a Mapping or an arbitrary object --------------------------

# Real OpenAI/Anthropic SDK responses are typed pydantic models, not dicts --
# `response.choices[0].message.tool_calls[0]` is a `ChatCompletionMessageToolCall`, and
# `response.content[i]` can be a `ToolUseBlock`. A caller who passes one of these straight
# through must not silently fall through to "unrecognized shape" just because `.get()`
# does not exist on it (C1). Every shape check below reads fields through `_field`/
# `_has_field` so the identical detection logic covers both Mapping and object input.


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _has_field(obj: Any, name: str) -> bool:
    if isinstance(obj, Mapping):
        return name in obj
    return hasattr(obj, name)


def _envelope(proposed: Any, exclude: tuple[str, ...]) -> dict[str, Any]:
    if isinstance(proposed, Mapping):
        return {k: v for k, v in proposed.items() if k not in exclude}
    # A non-Mapping object: there is no generic way to enumerate "every other field", so
    # only the two that matter for rendering a rewrite back in a shape the caller's
    # provider will accept (`id`, `type`) are preserved.
    return {k: _field(proposed, k) for k in ("id", "type") if k not in exclude and _has_field(proposed, k)}


def _tool_use_blocks(content: Any) -> list[Any]:
    """Every `type == "tool_use"` block inside an Anthropic-shaped content list."""
    if not isinstance(content, list):
        return []
    return [block for block in content if isinstance(block, Mapping) and block.get("type") == "tool_use"]


def _extract_bundle(proposed: Any) -> list[Any] | None:
    """Returns the individual tool-call-shaped items `proposed` bundles, or `None` if
    `proposed` is itself a single candidate (the common case).

    A caller can hand this adapter a raw provider response -- an OpenAI chat message
    (`response.choices[0].message`) or an Anthropic content list -- which carries zero,
    one, or several tool calls alongside (or instead of) a text answer. Detecting a
    bundle BEFORE single-shape recognition is what stops a message that pairs
    `content=None` with one or more `tool_calls` from ever being read as an empty,
    harmless final answer (the exact fail-open this function exists to close).
    """
    if isinstance(proposed, list):
        return proposed

    tool_calls = _field(proposed, "tool_calls", None)
    if isinstance(tool_calls, list) and tool_calls:
        return tool_calls

    tool_use = _tool_use_blocks(_field(proposed, "content", None))
    if tool_use:
        return tool_use

    return None


def _final_answer_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    if isinstance(content, list):
        return _message_text(content)
    return str(content)


def _normalize_single(proposed: Any) -> tuple[CandidateAction, _Shape, dict[str, Any], _Naming]:
    """Recognize exactly ONE of the four documented shapes in `proposed` (already
    unbundled by `_normalize_proposed`), or escalate. Never defaults an unrecognized
    mapping or object to a final answer -- only a bare `str`, or something that
    explicitly carries a `content` field the way the brief's documented final-answer
    shape does, reads as one (C1: "send any other unrecognised mapping or object to
    escalate ... never to final answer").
    """
    if isinstance(proposed, str):
        _check_content_length(proposed)
        return CandidateAction(type=ActionType.RESPOND, content=proposed, final=True), _Shape.FINAL_STR, {}, _EMPTY_NAMING

    function = _field(proposed, "function")
    function_name = _field(function, "name") if function is not None else None
    if isinstance(function_name, str):
        envelope = _envelope(proposed, exclude=("function",))
        arguments = _parse_openai_arguments(_field(function, "arguments"))
        action, naming = _tool_call_action(function_name, arguments)
        return action, _Shape.OPENAI, envelope, naming

    if _field(proposed, "type") == "tool_use" and isinstance(_field(proposed, "name"), str):
        envelope = _envelope(proposed, exclude=("name", "input"))
        raw_input = _field(proposed, "input")
        arguments = raw_input if isinstance(raw_input, Mapping) else {}
        action, naming = _tool_call_action(_field(proposed, "name"), arguments)
        return action, _Shape.ANTHROPIC, envelope, naming

    name = _field(proposed, "name")
    if isinstance(name, str) and not _has_field(proposed, "content"):
        envelope = _envelope(proposed, exclude=("name", "arguments"))
        arguments = _coerce_plain_arguments(_field(proposed, "arguments"))
        action, naming = _tool_call_action(name, arguments)
        return action, _Shape.PLAIN, envelope, naming

    if _has_field(proposed, "content"):
        content = _final_answer_text(_field(proposed, "content"))
        _check_content_length(content)
        envelope = _envelope(proposed, exclude=("content",))
        return (
            CandidateAction(type=ActionType.RESPOND, content=content, final=True),
            _Shape.FINAL_MESSAGE,
            envelope,
            _EMPTY_NAMING,
        )

    raise _GuardEscalate(
        GUARD_UNRECOGNIZED_ACTION_SHAPE,
        f"`proposed` ({type(proposed).__name__}) did not match any recognized tool-call "
        "or final-answer shape; refusing to guess rather than defaulting to a harmless "
        "final answer.",
    )


def _normalize_proposed(proposed: Any) -> tuple[CandidateAction, _Shape, dict[str, Any], _Naming]:
    bundle = _extract_bundle(proposed)
    if bundle is None:
        return _normalize_single(proposed)

    if len(bundle) > 1:
        # Judging only the first would silently allow every other call in the batch --
        # a fail-open on the rest (C1). The caller is expected to call `check()` once
        # per tool call, which is also how a real agent loop should execute them: each
        # gated (and potentially rewritten or blocked) on its own.
        raise _GuardEscalate(
            GUARD_MULTIPLE_TOOL_CALLS,
            f"{len(bundle)} tool calls arrived in one `proposed` value; call `check()` "
            "once per call so each is judged on its own.",
        )
    if len(bundle) == 0:
        raise _GuardEscalate(GUARD_UNRECOGNIZED_ACTION_SHAPE, "no tool call and no content to judge.")

    return _normalize_single(bundle[0])


def _restore_nested(value: Any) -> Any:
    """Undo `_stringify_argument`'s JSON-folding for rendering a rewrite back out, so a
    caller gets real nested structure instead of a doubly-encoded string (I4). Only a
    value that still parses as a JSON object/array is restored; a value redaction turned
    into non-JSON text stays a string, which is still safe, just not perfectly
    round-tripped.
    """
    if isinstance(value, str) and value[:1] in "{[":
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def _restore_arguments(arguments: Mapping[str, Any], key_by_sanitized: Mapping[str, str]) -> dict[str, Any]:
    return {key_by_sanitized.get(key, key): _restore_nested(value) for key, value in arguments.items()}


def _render_rewritten(
    shape: _Shape,
    envelope: dict[str, Any],
    action: CandidateAction,
    naming: _Naming,
    declared_tools: Mapping[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    """`rewritten` comes back in the caller's own shape (task-2-brief.md): OpenAI in,
    OpenAI out with `arguments` re-serialized to a JSON string; Anthropic in, Anthropic
    out with `input` as a dict; plain in, plain out. Nested argument values and the
    caller's own tool/key spelling are restored (I4), not left in this module's internal
    sanitized/flattened form.

    Returns `(rendered, escalate_reason)`. `escalate_reason` is non-None when the
    rewrite would substitute a DIFFERENT tool than the one proposed (e.g. `email_send`
    downgraded to `email_draft`), the caller declared at least one tool somewhere in
    its policy (`declared_tools` is non-empty -- see `HarisGuard.__init__`'s comment
    for why this checks the UNION of all three policy lists, not `allowed_tools`
    alone), and the substituted tool is not among them -- handing back a tool name the
    caller's agent may not even have is itself a fail-open (I4). When the caller
    declared NO tools at all, there is no vocabulary to check against, so this renders
    the substitution unconditionally, exactly as `/v1/decision` itself would (matching
    `rewrite.py`/`planner.py`'s own convention that an empty `allowed_tools` means
    unrestricted, not empty). A rewrite that keeps the same tool (content/argument
    redaction only) is never affected by this check either way.
    """
    if shape not in (_Shape.OPENAI, _Shape.ANTHROPIC, _Shape.PLAIN):
        return {**envelope, "content": action.content}, None

    sanitized_original = _safe_tool_name(naming.original_tool) if naming.original_tool else None
    if action.tool == sanitized_original:
        out_tool = naming.original_tool or action.tool
    elif not declared_tools:
        # Nothing declared anywhere: unrestricted, so there is no caller spelling to
        # restore to either -- this module's own sanitized form is all there is.
        out_tool = action.tool
    else:
        declared = declared_tools.get(action.tool)
        if declared is None:
            return None, GUARD_REWRITE_TOOL_UNDECLARED
        out_tool = declared

    restored_args = _restore_arguments(action.arguments, naming.key_by_sanitized)

    if shape is _Shape.OPENAI:
        return {**envelope, "function": {"name": out_tool, "arguments": json.dumps(restored_args)}}, None
    if shape is _Shape.ANTHROPIC:
        return {**envelope, "name": out_tool, "input": restored_args}, None
    return {**envelope, "name": out_tool, "arguments": restored_args}, None  # PLAIN


def _sanitize_tool_list(names: Sequence[str] | None, declared: dict[str, str] | None = None) -> list[str]:
    """Sanitize a caller-supplied policy tool list the SAME way `_safe_tool_name`
    sanitizes the actual candidate action's tool -- otherwise `wire-transfer` in policy
    and `wire_transfer` on the wire never compare equal, and a hyphenated or
    differently-cased gate silently stops gating (C4). `declared`, when given,
    accumulates sanitized -> the caller's own original spelling (first occurrence wins),
    so a rewrite can later be rendered back in the vocabulary the caller actually uses.
    """
    out: list[str] = []
    for raw in names or ():
        if not isinstance(raw, str):
            continue
        safe = _safe_tool_name(raw)
        if declared is not None:
            declared.setdefault(safe, raw)
        out.append(safe)
    return out


class HarisGuard:
    """The in-process front door. One instance per fixed policy; call `check()` per action.

    One instance should also correspond to one conversation: see `check()`'s docstring
    for what that buys (and costs) around `run_id`.
    """

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
        # A tool counts as "declared" if it is named in ANY of the three policy lists --
        # allowed_tools, consequential_tools, or confirmation_required_tools -- and
        # `_render_rewritten` reads the UNION of all three (round 2 review, reconciling
        # two opposite-pulling round-1 findings). The two readings that were each tried
        # and rejected first, recorded here so a future edit does not silently reinstate
        # either:
        #   - allowed_tools ALONE: matches nothing else in this codebase.
        #     rewrite.py:163 and planner.py:348 both treat an EMPTY allowed_tools as
        #     UNRESTRICTED, not "nothing is permitted" -- the guard's default
        #     configuration (no allowed_tools set at all) would then escalate every
        #     tool-substituting rewrite the core itself would happily perform, which is
        #     over-escalation on the guard's own most common configuration.
        #   - no check at all (the pre-round-1 behaviour): handed a caller a downgraded
        #     tool name (e.g. email_send -> email_draft) they never declared having,
        #     which is its own fail-open if the caller's agent has no such tool.
        # The reconciliation: if the union of all three lists is EMPTY, nothing was
        # declared at all, so there is no caller vocabulary to check against and this
        # guard renders a rewrite exactly like /v1/decision would (unrestricted, same
        # as rewrite.py's own convention). If the union is NON-EMPTY, the caller has
        # opted into a specific toolset, and a substituted tool must be a member of it
        # or the rewrite is declined in favour of an escalate.
        declared_tools: dict[str, str] = {}
        sanitized_allowed = _sanitize_tool_list(allowed_tools, declared_tools)
        sanitized_consequential = _sanitize_tool_list(consequential_tools, declared_tools)
        sanitized_confirmation = _sanitize_tool_list(confirmation_required_tools, declared_tools)
        self._declared_tools = declared_tools

        self._policy_context: dict[str, Any] = {
            "policy_id": policy_id,
            "allowed_tools": sanitized_allowed,
            "consequential_tools": sanitized_consequential,
            "confirmation_required_tools": sanitized_confirmation,
            "internal_email_domains": list(internal_email_domains) if internal_email_domains is not None else [],
            "rules": list(rules) if rules is not None else [],
        }
        self._settings = settings
        # No goal-derived default (see the module docstring): one random value per
        # instance, generated once, so every call through this SAME instance shares
        # haris/recall.py's taint memory, and no two different instances ever do.
        self._default_run_id = f"guard-{uuid.uuid4().hex}"
        # `step_id` defaults to a per-instance counter (task-2-brief.md). Named
        # `_step_counter`, not `_step_id`/`step_id`: this file's own module docstring
        # explains why no attribute here may be named exactly `run_id` or `step_id`.
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
        """Judge one candidate action and return a `Verdict`. Never raises.

        `goal` is the authenticated user's own request -- the only source of
        instruction authority (`haris/authority.py`). `proposed` is the action to
        judge, in any shape `_normalize_proposed` recognizes: an OpenAI tool call, an
        Anthropic `tool_use` block, a plain `{"name", "arguments"}` mapping, a bare
        final-answer string, or a raw provider message/response object carrying one of
        those. An unrecognized shape, or one bundling more than one tool call in a
        single `proposed` value, escalates (`GUARD_UNRECOGNIZED_ACTION_SHAPE` /
        `GUARD_MULTIPLE_TOOL_CALLS`) rather than silently passing as a harmless final
        answer -- call `check()` once per tool call if a turn proposes several.

        `run_id`: pass your own to remember tainted values across calls in the same
        conversation (`haris/recall.py`) -- e.g. so a secret read on turn 1 is still
        caught if the agent tries to leak it on turn 9, even once it has scrolled out
        of `messages`. Without one, this INSTANCE's own random default (set once at
        construction) is used, so repeated calls through the same `HarisGuard` still
        share memory with each other; two different instances never do. Rule of thumb:
        one `HarisGuard` per conversation.

        `confirmations`: a list of `Verdict.action_digest` values from a PRIOR escalated
        call for a confirmation-gated tool -- pass the digest back here once a human has
        actually approved that exact action, and it is allowed through on the next
        call. Approval is a fact about a previously recorded digest, never a claim in
        `proposed`'s own text (`haris/lifecycle.py`); a differently-shaped resubmission
        will not match.
        """
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
        try:
            action, shape, envelope, naming = _normalize_proposed(proposed)
        except _GuardEscalate as escalate:
            # Caught here, not by check()'s outer `except Exception`, so the specific
            # reason code survives instead of collapsing into HARIS_INTERNAL_ERROR.
            return _guard_escalate(escalate.reason_code, escalate.explanation)

        action_digest = action.digest()
        resolved_run_id = run_id if run_id else self._default_run_id
        resolved_step_id = step_id if step_id is not None else self._next_step()

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
            rendered, escalate_reason = _render_rewritten(
                shape, envelope, decision.rewritten_action, naming, self._declared_tools
            )
            if escalate_reason is not None:
                return Verdict(
                    decision="escalate",
                    risk=decision.risk_score,
                    confidence=decision.confidence,
                    reason_codes=[*decision.reason_codes, escalate_reason][:16],
                    explanation=(
                        "HARIS would substitute a tool not declared in this guard's "
                        "allowed_tools; deferring to a human rather than offering it."
                    )[:500],
                    rewritten=None,
                    metadata=dict(decision.metadata),
                    action_digest=action_digest,
                )
            rewritten = rendered

        return Verdict(
            decision=decision.decision.value,
            risk=decision.risk_score,
            confidence=decision.confidence,
            reason_codes=list(decision.reason_codes),
            explanation=decision.explanation or "",
            rewritten=rewritten,
            metadata=dict(decision.metadata),
            action_digest=action_digest,
        )
