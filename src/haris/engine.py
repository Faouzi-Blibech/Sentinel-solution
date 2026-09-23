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
from sentinel.core.actions import CandidateAction, Decision, DefenseDecision
from sentinel.core.provenance import Sensitivity
from sentinel.defenses.interface import DefenseRequest

from haris.authority import assess_authority, assess_memory_authority
from haris.capability import assess_argument_origin
from haris.config import SETTINGS, Settings
from haris.dataflow import assess_dataflow
from haris.fusion import fuse
from haris.journal import Journal
from haris.lifecycle import assess_confirmation, target_action
from haris.planner import assess_plan
from haris.policy import PolicyView
from haris.recall import tainted_values
from haris.rewrite import safer_alternative
from haris.signals import CONSEQUENTIAL_WITHOUT_CONFIRMATION, SENSITIVE_TO_EXTERNAL_SINK, Signal
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


def decide_detailed(
    request: DefenseRequest, settings: Settings = SETTINGS
) -> tuple[DefenseDecision, dict[str, Any]]:
    started = time.perf_counter()
    policy = PolicyView(request.policy_context)
    view = TrustView(request)
    timings: dict[str, float] = {}

    # Every stage judges the action that would actually take effect: a confirmation
    # request is a wrapper around a real call, and judging the wrapper laundered it.
    effective = target_action(request.candidate_action)

    mark = time.perf_counter()
    signals: list[Signal] = assess_authority(view, effective) if settings.authority_enabled else []
    timings["authority"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    plan_signals = assess_plan(request, policy) if settings.plan_enabled else []
    signals += plan_signals
    timings["plan"] = round((time.perf_counter() - mark) * 1000, 3)

    mark = time.perf_counter()
    lifecycle_signals = assess_confirmation(request, policy, view) if settings.lifecycle_enabled else []
    signals += lifecycle_signals
    timings["lifecycle"] = round((time.perf_counter() - mark) * 1000, 3)

    # CaMeL's argument-origin check: independent of plan/lifecycle, so it must NOT feed
    # `unauthorized` below -- that flag decides whether recalled memory counts as
    # authority, a different question from where a routing argument's value came from.
    # It DOES need to know whether lifecycle's own gate already fired (I1): stacking an
    # independent escalate-band signal on top of an already-firing confirmation gate
    # noisy-ORs past the block threshold, breaking capability's own "escalate, never
    # block" contract for a case the gate already covers.
    mark = time.perf_counter()
    confirmation_pending = any(
        s.code == CONSEQUENTIAL_WITHOUT_CONFIRMATION and s.value > 0.0 for s in lifecycle_signals
    )
    capability_signals = (
        assess_argument_origin(request, view, policy, confirmation_pending)
        if settings.capability_enabled
        else []
    )
    signals += capability_signals
    timings["capability"] = round((time.perf_counter() - mark) * 1000, 3)

    # Recalled memory only counts as authority when something else already says this
    # action was not authorized. Otherwise the agent is simply using a fact it noted.
    unauthorized = any(s.value > 0.0 for s in plan_signals + lifecycle_signals)
    if settings.memory_enabled:
        signals += assess_memory_authority(view, effective, unauthorized)

    mark = time.perf_counter()
    flow_signals, flow_meta = (
        assess_dataflow(request, view, policy, settings) if settings.dataflow_enabled else ([], {})
    )
    signals += flow_signals
    timings["dataflow"] = round((time.perf_counter() - mark) * 1000, 3)

    result = fuse(signals)

    # Decision ladder. Prefer a safer equivalent over an outright block: the official
    # score is a geometric mean, so needless blocking is disproportionately expensive.
    # Recall-backed too, so a rewrite redacts a value remembered from an earlier request
    # in this run and not just one visible in this one (report.md 8.1).
    tainted = tainted_values(request, view, Sensitivity.CONFIDENTIAL, settings)

    # `safer_alternative` scans the whole action for tainted content -- real cost on a
    # large body -- and its answer is only ever used in the three branches below. Every
    # ALLOW used to pay for it anyway (I3: most of the measured worst-case latency), so
    # it is computed here, lazily, only where a rewrite could actually be offered.
    def alternative() -> CandidateAction | None:
        return (
            safer_alternative(request.candidate_action, policy, tainted, reasons=result.active_codes)
            if settings.rewrite_enabled
            else None
        )

    # A detected leak is never delegated to a human. The kit's simulated human approves an
    # escalation iff its envelope -- tool and match keys -- matches a legitimate step, and
    # never reads content; so an escalated draft to the vendor carrying an encoded token
    # looks like the real reply and is approved. Escalation is only safe when the danger
    # is in the envelope. For a leak the answer is a provably clean rewrite, or a block.
    leak = SENSITIVE_TO_EXTERNAL_SINK in result.active_codes
    if leak:
        alt = alternative()
        decision, rewritten = (Decision.REWRITE, alt) if alt is not None else (Decision.BLOCK, None)
    elif result.risk_score >= settings.block_threshold:
        alt = alternative()
        decision, rewritten = (Decision.REWRITE, alt) if alt is not None else (Decision.BLOCK, None)
    elif result.risk_score >= settings.escalate_threshold:
        alt = alternative()
        decision, rewritten = (Decision.REWRITE, alt) if alt is not None else (Decision.ESCALATE, None)
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
        metadata=_trim_metadata(metadata, settings.max_metadata_bytes),
    )
    return verdict, metadata


def decide(request: DefenseRequest, settings: Settings = SETTINGS) -> DefenseDecision:
    """The contract entry point. Callers wanting the untrimmed metadata use decide_detailed."""
    return decide_detailed(request, settings)[0]


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
