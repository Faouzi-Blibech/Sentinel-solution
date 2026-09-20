"""Reason-code vocabulary and the signal record rendered by the observability layer.

Codes must match ^[A-Z][A-Z0-9_]{1,63}$ and a decision carries at most 16 of them.
"""

from __future__ import annotations

from dataclasses import dataclass

UNTRUSTED_INSTRUCTION_AUTHORITY = "UNTRUSTED_INSTRUCTION_AUTHORITY"
CAPABILITY_DRIFT = "CAPABILITY_DRIFT"
GOAL_PROHIBITION = "GOAL_PROHIBITION"
EFFECT_ESCALATION = "EFFECT_ESCALATION"
TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"
SENSITIVE_TO_EXTERNAL_SINK = "SENSITIVE_TO_EXTERNAL_SINK"
ENCODED_PAYLOAD_DETECTED = "ENCODED_PAYLOAD_DETECTED"
CONSEQUENTIAL_WITHOUT_CONFIRMATION = "CONSEQUENTIAL_WITHOUT_CONFIRMATION"
FORGED_CONFIRMATION = "FORGED_CONFIRMATION"
UNTRUSTED_MEMORY_AUTHORITY = "UNTRUSTED_MEMORY_AUTHORITY"
TRUSTED_POLICY_CONFLICT = "TRUSTED_POLICY_CONFLICT"
GOAL_ALIGNED = "GOAL_ALIGNED"
HARIS_INTERNAL_ERROR = "HARIS_INTERNAL_ERROR"

REASON_CODES = frozenset(
    {
        UNTRUSTED_INSTRUCTION_AUTHORITY,
        CAPABILITY_DRIFT,
        GOAL_PROHIBITION,
        EFFECT_ESCALATION,
        TOOL_NOT_PERMITTED,
        SENSITIVE_TO_EXTERNAL_SINK,
        ENCODED_PAYLOAD_DETECTED,
        CONSEQUENTIAL_WITHOUT_CONFIRMATION,
        FORGED_CONFIRMATION,
        UNTRUSTED_MEMORY_AUTHORITY,
        TRUSTED_POLICY_CONFLICT,
        GOAL_ALIGNED,
        HARIS_INTERNAL_ERROR,
    }
)


@dataclass(frozen=True)
class Signal:
    code: str
    weight: float
    value: float
    detail: str = ""

    @property
    def contribution(self) -> float:
        return round(self.weight * self.value, 6)

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "weight": self.weight,
            "value": self.value,
            "contribution": self.contribution,
            "detail": self.detail[:120],
        }
