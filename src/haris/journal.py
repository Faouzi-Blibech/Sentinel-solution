"""HARIS records its own reasoning, because the simulator's trace does not.

The run artifact keeps a DecisionRecord of decision, risk_score, confidence and
reason_codes, and drops the decision metadata entirely. Trust levels never reach the
artifact at all -- observations carry bare provenance ids. So the two panels that
actually explain a decision, the risk decomposition and the trust chain, have no data
source in the official trace.

This journal supplies them. The dashboard joins it to the simulator trace on
(run_id, step_id): the trace says what happened, the journal says why.

Writing is strictly best effort. A journal failure must never reach the decision path,
because the simulator fails CLOSED and would then block every action.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sentinel.core.actions import DefenseDecision
from sentinel.defenses.interface import DefenseRequest

DEFAULT_PATH = Path("artifacts") / "haris" / "journal.jsonl"
PREVIEW_CHARS = 400
ENV_PATH = "HARIS_JOURNAL_PATH"
ENV_DISABLE = "HARIS_JOURNAL_DISABLED"


def _preview(text: str | None) -> str:
    if not text:
        return ""
    return text[:PREVIEW_CHARS]


def _action_summary(action: Any) -> dict[str, Any]:
    return {
        "type": action.type.value,
        "tool": action.tool,
        "arguments": dict(action.arguments),
        "content": _preview(action.content),
        "final": action.final,
        "digest": action.digest(),
    }


class Journal:
    """Append-only JSONL record of every decision HARIS makes."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else Path(os.environ.get(ENV_PATH, DEFAULT_PATH))
        self.enabled = os.environ.get(ENV_DISABLE, "").strip().lower() not in {"1", "true", "yes"}
        self._seq = 0

    def record(
        self,
        request: DefenseRequest,
        decision: DefenseDecision,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        try:
            entry = self._entry(request, decision, metadata)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            self._seq += 1
        except Exception:  # noqa: BLE001 -- observability must never break the defense
            return

    def _entry(
        self,
        request: DefenseRequest,
        decision: DefenseDecision,
        metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        observation = request.observation
        return {
            "seq": self._seq,
            "run_id": request.run_id,
            "step_id": request.step_id,
            "user_goal": request.user_goal,
            "action": _action_summary(request.candidate_action),
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "confidence": decision.confidence,
            "reason_codes": list(decision.reason_codes),
            "explanation": decision.explanation,
            "rewritten_action": (
                _action_summary(decision.rewritten_action) if decision.rewritten_action is not None else None
            ),
            # Untrimmed when the caller supplies it; the decision's own copy is capped at 4096 bytes.
            "metadata": metadata if metadata is not None else dict(decision.metadata),
            "provenance": [
                {
                    "id": record.id,
                    "source_type": record.provenance.source_type.value,
                    "source_id": record.provenance.source_id,
                    "trust_level": record.provenance.trust_level.value,
                    "sensitivity": record.provenance.sensitivity.value,
                    "origin_actor": record.provenance.origin_actor,
                    "retrieved_via": record.provenance.retrieved_via,
                }
                for record in request.provenance
            ],
            "observation": (
                {
                    "kind": observation.kind,
                    "provenance_ids": list(observation.provenance_ids),
                    "content": _preview(observation.content),
                }
                if observation is not None
                else None
            ),
            "conversation": [
                {
                    "role": item.role,
                    "kind": item.kind,
                    "provenance_ids": list(item.provenance_ids),
                    "content": _preview(item.content),
                }
                for item in request.conversation
            ],
            "history": {
                "steps_taken": request.history_digest.steps_taken,
                "turn_index": request.history_digest.turn_index,
                "blocked_count": request.history_digest.blocked_count,
                "escalated_count": request.history_digest.escalated_count,
                "least_trusted_seen": request.history_digest.least_trusted_seen,
                "most_sensitive_seen": request.history_digest.most_sensitive_seen,
            },
        }
