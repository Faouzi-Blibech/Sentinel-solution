"""The rewrite ladder: keep the user's intent, drop the unsafe effect.

Rewrite is how the defense preserves utility while staying safe. Because the official
score is a weighted geometric mean, an unnecessary BLOCK is disproportionately
expensive, so a safe equivalent is always preferred to a refusal.

Two rewrites are available, and the distinction between them was forced by evidence.

1. Communication downgrade (send -> draft). Both tools act on the *same message*, so
   the arguments carry over unchanged and the rewritten call is always well formed.

2. Content redaction. For respond and memory_write we strip tainted values from the
   text and keep the legitimate remainder.

Lifecycle downgrades (execute/confirm/approve -> prepare) are deliberately NOT offered.
Observed in a real run: payment_execute(payment_id) was rewritten to
payment_prepare(payment_id), which the gateway rejected because payment_prepare
creates a new payment and requires account_id, amount, beneficiary_id and reference.
A rewrite whose arguments cannot be valid wastes the step and reads as a broken
defense, so those actions fall through to ESCALATE or BLOCK instead.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sentinel.core.actions import ActionType, CandidateAction

from haris.encodings import normalize
from haris.policy import PolicyView
from haris.signals import GOAL_PROHIBITION, SENSITIVE_TO_EXTERNAL_SINK

REDACTION = "[redacted]"

# Arguments that address the action rather than carry its content. Kept in step with
# haris.dataflow._DESTINATION_KEYS: both answer "where does this go".
ROUTING_KEYS = frozenset({"to", "recipient", "destination", "url", "endpoint", "address", "email"})

# Only downgrades where both tools provably act on the same payload.
_SAFE_DOWNGRADES = {"send": "draft", "post": "draft", "publish": "draft"}

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-/+]{6,}")


def _downgraded_name(tool: str) -> str | None:
    parts = tool.split("_")
    for index, part in enumerate(parts):
        replacement = _SAFE_DOWNGRADES.get(part)
        if replacement is not None:
            candidate = parts.copy()
            candidate[index] = replacement
            return "_".join(candidate)
    return None


def _redact(text: str, tainted: Iterable[str]) -> tuple[str, bool]:
    needles = {n for n in tainted if n}
    if not needles:
        return text, False
    changed = False

    def replace(match: re.Match[str]) -> str:
        nonlocal changed
        if normalize(match.group(0)) in needles:
            changed = True
            return REDACTION
        return match.group(0)

    return _TOKEN.sub(replace, text), changed


def _redact_arguments(
    arguments: dict[str, object], tainted: Iterable[str]
) -> tuple[dict[str, object], bool]:
    """Strip tainted values from message content, never from a routing argument.

    Redacting a destination yields "[redacted]@collector.example", which is not an
    address. A rewrite whose arguments cannot be valid wastes the step and reads as a
    broken defense, so a taint sitting in the destination means there is no safe
    substitute and the action must be refused outright.
    """
    needles = {n for n in tainted if n}
    out: dict[str, object] = {}
    changed = False
    for key, value in arguments.items():
        if isinstance(value, str) and key.lower() not in ROUTING_KEYS:
            replaced, hit = _redact(value, needles)
            changed = changed or hit
            out[key] = replaced
        else:
            out[key] = value
    return out, changed


def _still_leaks(arguments: dict[str, object], tainted: Iterable[str]) -> bool:
    """A tainted value can survive redaction by being the destination itself."""
    needles = {n for n in tainted if n}
    rendered = normalize(" ".join(str(v) for v in arguments.values()))
    return any(needle in rendered for needle in needles)


def safer_alternative(
    action: CandidateAction,
    policy: PolicyView,
    tainted: Iterable[str] | None = None,
    reasons: Iterable[str] | None = None,
) -> CandidateAction | None:
    """A safe equivalent of an unsafe action, or None when none exists.

    `reasons` are the reason codes that fired, because a substitution is only safer if
    it addresses the thing that was wrong. Downgrading the tool while copying the
    arguments across was not: email_send(to=<external>, body=<token>) became
    email_draft with the same recipient and the same token, and email_draft is itself a
    sink, so the canary still reached an untrusted destination. The rewrite turned a
    block into a leak.
    """
    codes = set(reasons or ())

    # An authenticated user who forbade this action did not ask for a neighbouring one.
    # Substituting here is disobedience, not mitigation, so a prohibition reaches BLOCK.
    if GOAL_PROHIBITION in codes:
        return None

    if action.type in (ActionType.RESPOND, ActionType.MEMORY_WRITE) and action.content:
        redacted, changed = _redact(action.content, tainted or ())
        if changed:
            try:
                return CandidateAction(type=action.type, content=redacted, final=action.final)
            except ValueError:
                return None
        return None

    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return None

    arguments, redacted_any = _redact_arguments(action.arguments, tainted or ())

    # When the objection is a leak, the leak has to be gone. If the tainted value is the
    # destination itself there is nothing left to substitute, so refuse the rewrite.
    if SENSITIVE_TO_EXTERNAL_SINK in codes:
        if not redacted_any:
            return None
        if _still_leaks(arguments, tainted or ()):
            return None

    target = _downgraded_name(action.tool)
    if target is None or target == action.tool:
        # Redaction alone is a real mitigation for a leak; without one there is nothing
        # safer on offer.
        if not redacted_any:
            return None
        target = action.tool
    # Only ever propose a tool the policy actually permits.
    elif policy.allowed_tools and target not in policy.allowed_tools:
        return None

    try:
        return CandidateAction(type=ActionType.TOOL_CALL, tool=target, arguments=arguments)
    except ValueError:
        return None
