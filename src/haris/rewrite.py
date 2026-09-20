"""The rewrite ladder: keep the user's intent, drop the irreversible effect.

Rewrite is how the defense preserves utility while staying safe. Because the official
score is a weighted geometric mean, an unnecessary BLOCK is disproportionately
expensive -- one weak component drags the whole product down. So whenever a reversible
equivalent of a consequential action exists, we prefer substituting it over refusing.

Downgrades are expressed as verb substitutions on the tool name, so a tool we have
never seen still downgrades correctly if it follows the naming convention.
"""

from __future__ import annotations

from sentinel.core.actions import ActionType, CandidateAction

from haris.policy import PolicyView

_DOWNGRADES = {
    "send": "draft",
    "execute": "prepare",
    "confirm": "prepare",
    "approve": "prepare",
    "close": "comment",
    "disable": "alert",
    "transfer": "prepare",
    "isolate": "prepare",
    "delete": "archive",
}


def _downgraded_name(tool: str) -> str | None:
    parts = tool.split("_")
    for index, part in enumerate(parts):
        replacement = _DOWNGRADES.get(part)
        if replacement is not None:
            candidate = parts.copy()
            candidate[index] = replacement
            return "_".join(candidate)
    return None


def safer_alternative(action: CandidateAction, policy: PolicyView) -> CandidateAction | None:
    """A reversible equivalent of a consequential action, or None if there is none."""
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
