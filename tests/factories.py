"""Builders for DefenseRequest fixtures. Keeps tests readable and contract-accurate."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.defenses.interface import (
    ConversationItem,
    DefenseRequest,
    HistoryDigest,
    ObservationView,
    ProvenanceRecord,
)


def make_provenance(
    trust: TrustLevel = TrustLevel.AUTHENTICATED_USER,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    source_type: SourceType = SourceType.USER,
) -> Provenance:
    return Provenance(
        source_type=source_type,
        source_id="src-1",
        trust_level=trust,
        origin_actor="actor",
        retrieved_via="chat",
        sensitivity=sensitivity,
        timestamp=datetime(2026, 9, 1, tzinfo=UTC),
    )


def make_request(
    *,
    user_goal: str = "Summarize the ticket and draft a reply.",
    provenance: dict[str, tuple[TrustLevel, Sensitivity]] | None = None,
    conversation: list[ConversationItem] | None = None,
    observation: ObservationView | None = None,
    action: CandidateAction | None = None,
    policy_context: dict[str, Any] | None = None,
    history_digest: HistoryDigest | None = None,
    step_id: int = 1,
    run_id: str = "test-run",
) -> DefenseRequest:
    records = [
        ProvenanceRecord(id=pid, provenance=make_provenance(trust, sens))
        for pid, (trust, sens) in (provenance or {}).items()
    ]
    return DefenseRequest(
        run_id=run_id,
        step_id=step_id,
        user_goal=user_goal,
        conversation=conversation or [],
        observation=observation,
        candidate_action=action
        or CandidateAction(type=ActionType.TOOL_CALL, tool="document_read", arguments={"doc_id": "D-1"}),
        policy_context=policy_context or {},
        provenance=records,
        history_digest=history_digest or HistoryDigest(),
    )
