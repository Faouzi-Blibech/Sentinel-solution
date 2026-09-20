"""The simulator's trace drops everything that explains a decision.

DecisionRecord keeps only decision, risk_score, confidence and reason_codes, and no
trust level ever reaches the artifact. So HARIS records its own reasoning; the
dashboard joins the two on (run_id, step_id).
"""

import json

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.engine import decide
from haris.journal import Journal
from tests.factories import make_request

POLICY = {
    "policy_id": "enterprise_standard",
    "allowed_tools": ["email_read", "email_draft", "email_send"],
    "consequential_tools": ["email_send"],
    "internal_email_domains": ["atlas.example"],
}


def _request():
    return make_request(
        user_goal="Summarize the invoice dispute and draft a reply.",
        provenance={"p": (TrustLevel.UNTRUSTED_EXTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool", kind="tool_result", content="reference CTR-SYN-906FAF7F88", provenance_ids=["p"]
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "billing@lumen-supplies.example", "body": "CTR-SYN-906FAF7F88"},
        ),
        policy_context=POLICY,
    )


def test_journal_writes_one_json_line_per_decision(tmp_path):
    path = tmp_path / "journal.jsonl"
    journal = Journal(path)
    request = _request()
    journal.record(request, decide(request))
    journal.record(request, decide(request))

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)


def test_journal_keeps_the_full_signal_decomposition(tmp_path):
    """The decision's own metadata is capped at 4096 bytes; the journal is not."""
    path = tmp_path / "journal.jsonl"
    request = _request()
    Journal(path).record(request, decide(request))

    entry = json.loads(path.read_text(encoding="utf-8").strip())
    assert entry["run_id"] == request.run_id
    assert entry["step_id"] == request.step_id
    assert entry["decision"] in {"allow", "block", "escalate", "rewrite"}
    codes = {s["code"] for s in entry["metadata"]["signals"]}
    assert "SENSITIVE_TO_EXTERNAL_SINK" in codes


def test_journal_records_resolved_trust_levels(tmp_path):
    """Trust never reaches the simulator artifact, so it must come from here."""
    path = tmp_path / "journal.jsonl"
    request = _request()
    Journal(path).record(request, decide(request))

    entry = json.loads(path.read_text(encoding="utf-8").strip())
    by_id = {p["id"]: p for p in entry["provenance"]}
    assert by_id["p"]["trust_level"] == "untrusted_external"
    assert by_id["p"]["sensitivity"] == "confidential"


def test_journal_records_the_action_and_the_goal(tmp_path):
    path = tmp_path / "journal.jsonl"
    request = _request()
    Journal(path).record(request, decide(request))

    entry = json.loads(path.read_text(encoding="utf-8").strip())
    assert entry["user_goal"].startswith("Summarize the invoice dispute")
    assert entry["action"]["tool"] == "email_send"
    assert entry["action"]["type"] == "tool_call"


def test_journal_never_raises_on_an_unwritable_path(tmp_path):
    """A journal failure must never take the defense down with it."""
    journal = Journal(tmp_path / "no" / "such" / "dir" / "journal.jsonl")
    request = _request()
    journal.record(request, decide(request))  # must not raise
