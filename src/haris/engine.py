"""Stage orchestration and the DefenseDecision builder.

The metadata payload written here is the contract the observability layer and the
evaluation harness both consume. Changing its shape breaks workstreams B and C.
"""

from __future__ import annotations

import json
import time
from typing import Any

from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import DefenseRequest

from haris.authority import assess_authority
from haris.config import SETTINGS
from haris.dataflow import assess_dataflow
from haris.fusion import fuse
from haris.planner import assess_plan
from haris.policy import PolicyView
from haris.rewrite import safer_alternative
from haris.secrets import extract_tainted_values
from haris.signals import Signal
from haris.trust import TrustView

METADATA_VERSION = "1.0"


def _trim_metadata(metadata: dict[str, Any], limit: int) -> dict[str, Any]:
    """Guarantee the 4096-byte contract bound by dropping detail, never structure."""
    if len(json.dumps(metadata)) <= limit:
        return metadata
    trimmed = dict(metadata)
    trimmed["signals"] = [
        {k: v for k, v in entry.items() if k != "detail"} for entry in trimmed.get("signals", [])
    ]
    if len(json.dumps(trimmed)) <= limit:
        return trimmed
    trimmed["signals"] = [e for e in trimmed["signals"] if e.get("contribution", 0) > 0][:8]
    trimmed["truncated"] = True
    if len(json.dumps(trimmed)) <= limit:
        return trimmed
    return {"haris_version": METADATA_VERSION, "truncated": True}


def _explain(decision: Decision, codes: list[str]) -> str:
    joined = ", ".join(codes[:4])
    if decision is Decision.ALLOW:
        return f"Action is consistent with the committed task; no blocking signal fired ({joined})."
    if decision is Decision.REWRITE:
        return f"Substituted a reversible equivalent because {joined} fired."
    if decision is Decision.ESCALATE:
        return f"Deferring to a human: {joined}."
    return f"Blocked: {joined}."


def decide(request: DefenseRequest) -> DefenseDecision:
    started = time.perf_counter()
    policy = PolicyView(request.policy_context)
    view = TrustView(request)
    timings: dict[str, float] = {}

    mark = time.perf_counter()
    signals: list[Signal] = assess_authority(view)
    timings["authority"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    signals += assess_plan(request, policy)
    timings["plan"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    flow_signals, flow_meta = assess_dataflow(request, view, policy)
    signals += flow_signals
    timings["dataflow"] = round((time.perf_counter() - mark) * 1000, 3)

    result = fuse(signals)

    # Decision ladder. Prefer a safer equivalent over an outright block: the official
    # score is a geometric mean, so needless blocking is disproportionately expensive.
    tainted = extract_tainted_values(view)
    alternative = safer_alternative(request.candidate_action, policy, tainted)
    if result.risk_score >= SETTINGS.block_threshold:
        decision, rewritten = (
            (Decision.REWRITE, alternative) if alternative is not None else (Decision.BLOCK, None)
        )
    elif result.risk_score >= SETTINGS.escalate_threshold:
        decision, rewritten = (
            (Decision.REWRITE, alternative) if alternative is not None else (Decision.ESCALATE, None)
        )
    else:
        decision, rewritten = Decision.ALLOW, None

    metadata: dict[str, Any] = {
        "haris_version": METADATA_VERSION,
        "signals": [s.as_dict() for s in signals],
        "trust": {
            "observation_trust": view.observation_trust().value,
            "least_trusted_seen": request.history_digest.least_trusted_seen,
            "most_sensitive_seen": request.history_digest.most_sensitive_seen,
        },
        "plan": {"policy_id": policy.policy_id, "tool": request.candidate_action.tool},
        "dataflow": flow_meta,
        "stage_timings_ms": timings,
        "total_ms": round((time.perf_counter() - started) * 1000, 3),
    }

    return DefenseDecision(
        decision=decision,
        risk_score=result.risk_score,
        confidence=result.confidence,
        reason_codes=result.active_codes,
        explanation=_explain(decision, result.active_codes)[:500],
        rewritten_action=rewritten,
        metadata=_trim_metadata(metadata, SETTINGS.max_metadata_bytes),
    )


def decide_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    request = DefenseRequest.model_validate(payload)
    return decide(request).model_dump(mode="json")
