"""HARIS as an in-process `Defense`, which is what makes a real ablation possible.

The HTTP service is the submitted surface. It is the wrong shape for an ablation: one
process serves one configuration, so measuring seven configurations would mean seven
servers and seven ports, and the numbers would be hard to trust.

The evaluator accepts a factory returning a `Defense`, so a configuration becomes an
argument instead of a deployment. Every ablation arm in `redteam/harness.py` is this
class with a different `Settings`, running the same decision code as the service.
"""

from __future__ import annotations

from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest

from haris.config import SETTINGS, Settings
from haris.engine import decide

# The service's fallback, restated here: an in-process defense that raises would abort
# the run rather than degrade it, and an ablation arm that crashes is not a measurement.
_SAFE_FALLBACK = DefenseDecision(
    decision=Decision.ESCALATE,
    risk_score=0.5,
    confidence=0.0,
    reason_codes=["HARIS_INTERNAL_ERROR"],
    explanation="HARIS could not evaluate this action; deferring to a human.",
)


class HarisDefense(Defense):
    """The submitted defense, with any subset of its stages switched off."""

    def __init__(self, settings: Settings = SETTINGS, name: str = "haris") -> None:
        self.settings = settings
        self.name = name

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        try:
            return decide(request, self.settings)
        except Exception:  # noqa: BLE001 -- never abort a run; mirror the service contract
            return _SAFE_FALLBACK


def variant(name: str, *disabled: str) -> type[Defense]:
    """A zero-argument factory for one ablation arm, as `evaluate()` expects."""
    settings = SETTINGS.without(*disabled)

    def build() -> Defense:
        return HarisDefense(settings, name=name)

    return build  # type: ignore[return-value]
