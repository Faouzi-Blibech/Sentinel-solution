from sentinel.core.actions import ActionType, CandidateAction

from haris.policy import PolicyView
from haris.rewrite import safer_alternative

POLICY = PolicyView({"allowed_tools": ["email_send", "email_draft", "payment_prepare", "payment_execute"]})


def test_send_is_downgraded_to_draft():
    action = CandidateAction(
        type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "a@b.example", "body": "hi"}
    )
    alternative = safer_alternative(action, POLICY)
    assert alternative is not None
    assert alternative.tool == "email_draft"
    assert alternative.arguments["body"] == "hi"


def test_execute_is_downgraded_to_prepare():
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="payment_execute", arguments={"payment_id": "P-1"})
    alternative = safer_alternative(action, POLICY)
    assert alternative is not None
    assert alternative.tool == "payment_prepare"


def test_no_alternative_when_target_not_in_policy():
    policy = PolicyView({"allowed_tools": ["email_send"]})
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "a@b.example"})
    assert safer_alternative(action, policy) is None


def test_read_action_has_no_downgrade():
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="email_read", arguments={"email_id": "E-1"})
    assert safer_alternative(action, POLICY) is None


def test_alternative_is_a_valid_candidate_action():
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "a@b.example"})
    alternative = safer_alternative(action, POLICY)
    assert alternative is not None
    assert alternative.type is ActionType.TOOL_CALL
    assert alternative.content is None  # tool_call actions take arguments only
