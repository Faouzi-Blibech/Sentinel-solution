from sentinel.core.actions import ActionType, CandidateAction

from haris.planner import assess_plan, commit
from haris.policy import PolicyView
from haris.signals import CAPABILITY_DRIFT, TOOL_NOT_PERMITTED
from tests.factories import make_request

POLICY = PolicyView(
    {
        "allowed_tools": ["email_read", "document_read", "email_draft"],
        "consequential_tools": ["email_send"],
        "internal_email_domains": ["atlas.example"],
    }
)


def test_commitment_authorizes_tools_the_goal_implies():
    commitment = commit("Read the ticket and draft a reply.", POLICY)
    assert commitment.authorizes("email_draft")


def test_tool_outside_policy_is_not_permitted():
    request = make_request(
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="payment_execute", arguments={"payment_id": "P-1"})
    )
    codes = {s.code for s in assess_plan(request, POLICY) if s.value > 0}
    assert TOOL_NOT_PERMITTED in codes


def test_allowed_but_ungrounded_tool_is_drift():
    """email_send is policy-consequential and unrelated to a read-only goal."""
    policy = PolicyView({"allowed_tools": ["email_read", "email_send"], "consequential_tools": ["email_send"]})
    request = make_request(
        user_goal="Read the latest partner newsletter and summarize it.",
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "x@y.example"}),
    )
    codes = {s.code for s in assess_plan(request, policy) if s.value > 0}
    assert CAPABILITY_DRIFT in codes


def test_goal_aligned_read_is_not_drift():
    request = make_request(
        user_goal="Read the latest partner newsletter and summarize it.",
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="email_read", arguments={"email_id": "EM-1"}),
    )
    codes = {s.code for s in assess_plan(request, POLICY) if s.value > 0}
    assert CAPABILITY_DRIFT not in codes
