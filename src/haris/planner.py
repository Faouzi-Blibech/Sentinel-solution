"""Capability commitment: control-flow integrity for the agent.

The authorized capability set is derived from the user goal, which is
AUTHENTICATED_USER by construction, and from the SYSTEM_POLICY allow-list. Nothing
the agent later reads can widen it. An action outside the set is drift.

The goal both grants and DENIES. A naive bag-of-words reading of
"...add a case note. Do not confirm or execute the payment."
sees the words "confirm" and "execute" and authorizes exactly what the user forbade.
So verbs are attributed to a grant or a prohibition according to whether they fall
inside a negation scope. A prohibition from the authenticated user is the strongest
signal available to this defense and outranks everything else.

Effect classes are inferred from the verb shape of the tool name rather than a
hard-coded per-domain table, so this generalizes to tools we have never seen and
carries no scenario-specific knowledge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.core.actions import ActionType
from sentinel.defenses.interface import DefenseRequest

from haris.policy import PolicyView
from haris.signals import CAPABILITY_DRIFT, GOAL_PROHIBITION, TOOL_NOT_PERMITTED, Signal

DRIFT_WEIGHT = 0.40
PERMISSION_WEIGHT = 0.50
# A prohibition from the authenticated user is decisive on its own.
PROHIBITION_WEIGHT = 0.95

_READ_VERBS = {"read", "search", "lookup", "list", "get", "fetch", "view", "correlate", "triage"}
_WRITE_VERBS = {"draft", "create", "note", "comment", "update", "prepare", "write", "save", "store"}
_CONSEQUENTIAL_VERBS = {
    "send", "execute", "confirm", "approve", "close", "disable", "transfer", "delete", "isolate",
}
_ALL_VERBS = _READ_VERBS | _WRITE_VERBS | _CONSEQUENTIAL_VERBS

_EFFECT_ORDER = {"read": 0, "write": 1, "consequential": 2, "unknown": 2}

_GOAL_TOKEN = re.compile(r"[a-z]{3,}")
_SENTENCE = re.compile(r"[.;!?\n]")
_NEGATION_CUE = re.compile(
    r"\b(do\s+not|don't|does\s+not|doesn't|must\s+not|mustn't|cannot|can't|never|"
    r"without|avoid|refrain\s+from|no\s+need\s+to|under\s+no\s+circumstances)\b",
    re.IGNORECASE,
)


def _verbs(tool: str) -> set[str]:
    return set(tool.lower().split("_"))


def effect_class(tool: str) -> str:
    verbs = _verbs(tool)
    if verbs & _CONSEQUENTIAL_VERBS:
        return "consequential"
    if verbs & _WRITE_VERBS:
        return "write"
    if verbs & _READ_VERBS:
        return "read"
    return "unknown"


def _effect_rank(effect: str) -> int:
    return _EFFECT_ORDER.get(effect, 2)


def parse_goal(user_goal: str) -> tuple[frozenset[str], frozenset[str]]:
    """Split the goal's verbs into (granted, denied) by negation scope.

    A negation cue denies every verb from the cue to the end of its sentence.
    """
    granted: set[str] = set()
    denied: set[str] = set()
    for sentence in _SENTENCE.split(user_goal.lower()):
        if not sentence.strip():
            continue
        cue = _NEGATION_CUE.search(sentence)
        if cue is None:
            granted.update(_GOAL_TOKEN.findall(sentence))
            continue
        granted.update(_GOAL_TOKEN.findall(sentence[: cue.start()]))
        denied.update(_GOAL_TOKEN.findall(sentence[cue.end() :]))
    # A verb explicitly forbidden is never also granted.
    granted -= denied
    return frozenset(granted), frozenset(denied & _ALL_VERBS)


@dataclass(frozen=True)
class Commitment:
    goal_tokens: frozenset[str]
    denied_verbs: frozenset[str]
    allowed_tools: frozenset[str]
    max_effect: str

    def prohibits(self, tool: str) -> bool:
        return bool(_verbs(tool) & self.denied_verbs)

    def authorizes(self, tool: str) -> bool:
        if self.prohibits(tool):
            return False
        if self.allowed_tools and tool not in self.allowed_tools:
            return False
        return _effect_rank(effect_class(tool)) <= _effect_rank(self.max_effect)


def commit(user_goal: str, policy: PolicyView) -> Commitment:
    """Freeze the capability set implied by the authenticated goal, before any observation."""
    granted, denied = parse_goal(user_goal)
    # The goal authorizes a consequential effect only if it asks for one, unnegated.
    if granted & _CONSEQUENTIAL_VERBS:
        max_effect = "consequential"
    elif granted & _WRITE_VERBS:
        max_effect = "write"
    else:
        max_effect = "read"
    return Commitment(
        goal_tokens=granted,
        denied_verbs=denied,
        allowed_tools=policy.allowed_tools,
        max_effect=max_effect,
    )


def assess_plan(request: DefenseRequest, policy: PolicyView) -> list[Signal]:
    action = request.candidate_action
    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return [
            Signal(code=GOAL_PROHIBITION, weight=PROHIBITION_WEIGHT, value=0.0, detail="not a tool call"),
            Signal(code=TOOL_NOT_PERMITTED, weight=PERMISSION_WEIGHT, value=0.0, detail="not a tool call"),
            Signal(code=CAPABILITY_DRIFT, weight=DRIFT_WEIGHT, value=0.0, detail="not a tool call"),
        ]

    tool = action.tool
    commitment = commit(request.user_goal, policy)

    prohibited = 1.0 if commitment.prohibits(tool) else 0.0
    permitted = 0.0 if (not policy.allowed_tools or policy.is_allowed(tool)) else 1.0
    drift = 0.0 if commitment.authorizes(tool) else 1.0

    return [
        Signal(
            code=GOAL_PROHIBITION,
            weight=PROHIBITION_WEIGHT,
            value=prohibited,
            detail=f"{tool} vs denied verbs {sorted(commitment.denied_verbs)}",
        ),
        Signal(
            code=TOOL_NOT_PERMITTED,
            weight=PERMISSION_WEIGHT,
            value=permitted,
            detail=f"{tool} vs policy allow-list",
        ),
        Signal(
            code=CAPABILITY_DRIFT,
            weight=DRIFT_WEIGHT,
            value=drift,
            detail=f"{tool} effect={effect_class(tool)} goal_max={commitment.max_effect}",
        ),
    ]
