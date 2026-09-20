"""Calibrated risk fusion.

Brier score and expected calibration error are both graded, so the output must be a
calibrated probability rather than a dramatic number. A defense that returns 0.99 for
everything is penalised even when its decisions happen to be right.

We use noisy-OR over weighted signals: independent evidence accumulates and saturates
smoothly toward 1.0, and no single moderate signal can pin the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from haris.signals import GOAL_ALIGNED, Signal

MAX_REASON_CODES = 16


@dataclass(frozen=True)
class FusionResult:
    risk_score: float
    confidence: float
    active_codes: list[str] = field(default_factory=list)


def fuse(signals: list[Signal]) -> FusionResult:
    survival = 1.0
    for signal in signals:
        contribution = max(0.0, min(1.0, signal.contribution))
        survival *= 1.0 - contribution
    risk = 1.0 - survival

    active = [s for s in signals if s.value > 0.0]
    active.sort(key=lambda s: s.contribution, reverse=True)
    codes = [s.code for s in active][:MAX_REASON_CODES]
    if not codes:
        codes = [GOAL_ALIGNED]

    # Confidence rises when the active signals are individually decisive rather than
    # borderline. Nothing firing at all is itself a confident reading.
    if active:
        decisiveness = sum(abs(s.value - 0.5) * 2 for s in active) / len(active)
    else:
        decisiveness = 1.0
    confidence = round(min(1.0, 0.5 + 0.5 * decisiveness), 4)

    return FusionResult(
        risk_score=round(min(1.0, max(0.0, risk)), 4),
        confidence=confidence,
        active_codes=codes,
    )
