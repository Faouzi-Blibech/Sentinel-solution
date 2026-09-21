"""Stage orchestration and the DefenseDecision builder.

The metadata payload written here is the contract the observability layer and the
evaluation harness both consume. Changing its shape breaks workstreams B and C.
"""

from __future__ import annotations

import json
import time
from copy import deepcopy
from typing import Any

from pydantic import ValidationError
from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import DefenseRequest

from haris.authority import assess_authority, assess_memory_authority
from haris.config import SETTINGS
from haris.dataflow import assess_dataflow
from haris.fusion import fuse
from haris.journal import Journal
from haris.lifecycle import assess_confirmation, target_action
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


def decide_detailed(request: DefenseRequest) -> tuple[DefenseDecision, dict[str, Any]]:
    started = time.perf_counter()
    policy = PolicyView(request.policy_context)
    view = TrustView(request)
    timings: dict[str, float] = {}

    # Every stage judges the action that would actually take effect: a confirmation
    # request is a wrapper around a real call, and judging the wrapper laundered it.
    effective = target_action(request.candidate_action)

    mark = time.perf_counter()
    signals: list[Signal] = assess_authority(view, effective)
    timings["authority"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    plan_signals = assess_plan(request, policy)
    signals += plan_signals
    timings["plan"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    lifecycle_signals = assess_confirmation(request, policy, view)
    signals += lifecycle_signals
    timings["lifecycle"] = round((time.perf_counter() - mark) * 1000, 3)

    # Recalled memory only counts as authority when something else already says this
    # action was not authorized. Otherwise the agent is simply using a fact it noted.
    unauthorized = any(s.value > 0.0 for s in plan_signals + lifecycle_signals)
    signals += assess_memory_authority(view, effective, unauthorized)

    mark = time.perf_counter()
    flow_signals, flow_meta = assess_dataflow(request, view, policy)
    signals += flow_signals
    timings["dataflow"] = round((time.perf_counter() - mark) * 1000, 3)

    result = fuse(signals)

    # Decision ladder. Prefer a safer equivalent over an outright block: the official
    # score is a geometric mean, so needless blocking is disproportionately expensive.
    tainted = extract_tainted_values(view)
    alternative = safer_alternative(
        request.candidate_action, policy, tainted, reasons=result.active_codes
    )
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
        "plan": {
            "policy_id": policy.policy_id,
            "tool": effective.tool,
            "action_type": request.candidate_action.type.value,
            "confirmed": effective.digest() in set(request.history_digest.confirmations_granted),
        },
        "dataflow": flow_meta,
        "stage_timings_ms": timings,
        "total_ms": round((time.perf_counter() - started) * 1000, 3),
    }

    verdict = DefenseDecision(
        decision=decision,
        risk_score=result.risk_score,
        confidence=result.confidence,
        reason_codes=result.active_codes,
        explanation=_explain(decision, result.active_codes)[:500],
        rewritten_action=rewritten,
        metadata=_trim_metadata(metadata, SETTINGS.max_metadata_bytes),
    )
    return verdict, metadata


def decide(request: DefenseRequest) -> DefenseDecision:
    """The contract entry point. Callers wanting the untrimmed metadata use decide_detailed."""
    return decide_detailed(request)[0]


MAX_PRUNE_PASSES = 8


def _drop(payload: Any, loc: tuple[Any, ...]) -> None:
    """Remove one value addressed by a pydantic error location."""
    target = payload
    for key in loc[:-1]:
        target = target[key]
    del target[loc[-1]]


def parse_request(payload: dict[str, Any]) -> DefenseRequest:
    """Validate leniently: ignore fields our pinned schema does not know about.

    The contract models are extra="forbid", so a single unrecognised field would send
    every action to the internal-error fallback. With the simulator failing CLOSED that
    blocks everything and drops benign utility below the eligibility gate, so unknown
    fields are pruned rather than treated as fatal. Pydantic reports exactly where they
    are, which is more reliable than introspecting the schema ourselves.
    """
    working = deepcopy(payload)
    for _ in range(MAX_PRUNE_PASSES):
        try:
            return DefenseRequest.model_validate(working)
        except ValidationError as error:
            extras = [e["loc"] for e in error.errors() if e["type"] == "extra_forbidden"]
            if not extras:
                raise
            for loc in extras:
                try:
                    _drop(working, loc)
                except (KeyError, IndexError, TypeError):
                    continue
    return DefenseRequest.model_validate(working)


_JOURNAL = Journal()


def decide_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    request = parse_request(payload)
    verdict, full_metadata = decide_detailed(request)
    _JOURNAL.record(request, verdict, full_metadata)
    return verdict.model_dump(mode="json")
