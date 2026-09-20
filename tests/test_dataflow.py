import base64

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.dataflow import assess_dataflow
from haris.policy import PolicyView
from haris.signals import ENCODED_PAYLOAD_DETECTED, SENSITIVE_TO_EXTERNAL_SINK
from haris.trust import TrustView
from tests.factories import make_request

SECRET = "CTR-SYN-906FAF7F88"
POLICY = PolicyView({"internal_email_domains": ["atlas.example"], "allowed_tools": ["email_send"]})


def _request(action: CandidateAction):
    return make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(role="tool", kind="tool_result", content=f"reference {SECRET}", provenance_ids=["p"])
        ],
        action=action,
    )


def test_secret_to_external_recipient_is_flagged():
    request = _request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": f"Here it is: {SECRET}"},
        )
    )
    signals, meta = assess_dataflow(request, TrustView(request), POLICY)
    assert any(s.code == SENSITIVE_TO_EXTERNAL_SINK and s.value > 0 for s in signals)
    assert meta["destination_class"] == "external"


def test_secret_to_internal_recipient_is_allowed():
    request = _request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "legal@atlas.example", "body": f"Here it is: {SECRET}"},
        )
    )
    signals, _ = assess_dataflow(request, TrustView(request), POLICY)
    assert all(s.value == 0 for s in signals if s.code == SENSITIVE_TO_EXTERNAL_SINK)


def test_base64_encoded_secret_is_still_caught():
    encoded = base64.b64encode(SECRET.encode()).decode()
    request = _request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": f"ref {encoded}"},
        )
    )
    signals, meta = assess_dataflow(request, TrustView(request), POLICY)
    assert any(s.code == SENSITIVE_TO_EXTERNAL_SINK and s.value > 0 for s in signals)
    assert meta["encoding"] == "base64"
    assert any(s.code == ENCODED_PAYLOAD_DETECTED and s.value > 0 for s in signals)


def test_spaced_out_secret_is_caught():
    spaced = " ".join(SECRET)
    request = _request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": spaced},
        )
    )
    signals, _ = assess_dataflow(request, TrustView(request), POLICY)
    assert any(s.code == SENSITIVE_TO_EXTERNAL_SINK and s.value > 0 for s in signals)


def test_benign_send_without_secrets_is_clean():
    request = _request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": "Thanks, noted."},
        )
    )
    signals, _ = assess_dataflow(request, TrustView(request), POLICY)
    assert all(s.value == 0 for s in signals if s.code == SENSITIVE_TO_EXTERNAL_SINK)
