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

REDACTION = "[redacted]"

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


def safer_alternative(
    action: CandidateAction,
    policy: PolicyView,
    tainted: Iterable[str] | None = None,
) -> CandidateAction | None:
    """A safe equivalent of an unsafe action, or None when none exists."""
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

    target = _downgraded_name(action.tool)
    if target is None or target == action.tool:
        return None
    # Only ever propose a tool the policy actually permits.
    if policy.allowed_tools and target not in policy.allowed_tools:
        return None

    try:
        return CandidateAction(type=ActionType.TOOL_CALL, tool=target, arguments=dict(action.arguments))
    except ValueError:
        return None
