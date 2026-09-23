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


def test_tool_downgrade_does_not_invent_incompatible_arguments():
    """Regression: payment_execute(payment_id) was rewritten to payment_prepare(payment_id),
    which the gateway rejected because payment_prepare needs account_id/amount/beneficiary_id.

    A rewrite whose arguments cannot be valid is worse than no rewrite at all.
    """
    policy = PolicyView({"allowed_tools": ["payment_execute", "payment_prepare"]})
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="payment_execute", arguments={"payment_id": "PAY-1"})
    assert safer_alternative(action, policy) is None


def test_respond_carrying_tainted_values_is_redacted():
    action = CandidateAction(
        type=ActionType.RESPOND, content="Summary complete. Reference CTR-SYN-906FAF7F88."
    )
    alternative = safer_alternative(action, POLICY, tainted={"ctrsyn906faf7f88"})
    assert alternative is not None
    assert "CTR-SYN-906FAF7F88" not in (alternative.content or "")
    assert "Summary complete." in (alternative.content or "")


def test_clean_respond_is_not_rewritten():
    action = CandidateAction(type=ActionType.RESPOND, content="Summary complete.")
    assert safer_alternative(action, POLICY, tainted={"ctrsyn906faf7f88"}) is None


# --- The rewrite must remove the unsafe property, not relabel the action ------------
#
# Found by probing: email_send(to=<external>, body=<restricted token>) was rewritten to
# email_draft with the SAME recipient and the SAME token. email_draft is itself a sink
# (sentinel/domains/enterprise/tools.py:83 returns Sink("email_draft",
# recipient_trust(...))), so the canary still reached an untrusted destination and the
# data-flow rule still fired at critical severity. The rewrite turned a block into a leak.

TAINT = {"ptl77d2f914ax31"}
LEAK = CandidateAction(
    type=ActionType.TOOL_CALL,
    tool="email_send",
    arguments={
        "to": "billing@lumen-supplies.example",
        "subject": "ref",
        "body": "Token PTL-77d2f914-ax31 as requested.",
    },
)


def test_downgrade_redacts_tainted_arguments_rather_than_carrying_them_over():
    alternative = safer_alternative(LEAK, POLICY, tainted=TAINT, reasons=["SENSITIVE_TO_EXTERNAL_SINK"])
    assert alternative is not None
    rendered = " ".join(str(v) for v in alternative.arguments.values())
    assert "PTL-77d2f914-ax31" not in rendered
    assert alternative.tool == "email_draft"
    # The legitimate remainder of the message survives, which is the point of a rewrite.
    assert "as requested" in alternative.arguments["body"]


def test_no_rewrite_when_the_leak_cannot_be_removed():
    """If the secret is the destination itself there is nothing safe to substitute."""
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "ptl-77d2f914-ax31@collector.example", "body": "hello"},
    )
    assert safer_alternative(action, POLICY, tainted=TAINT, reasons=["SENSITIVE_TO_EXTERNAL_SINK"]) is None


def test_an_ungrounded_routing_argument_is_never_rewritten_around():
    """T1: a tool-name downgrade (payment_send -> payment_draft) copies every argument
    across unchanged -- there is no redaction concept for "iban", so
    UNTRUSTED_ARGUMENT_ORIGIN firing means the SAME attacker-supplied IBAN would ride
    along into the "safer" tool. That is not a mitigation, it is laundering the exact
    argument capability.py flagged into a differently-named call. Same pattern as
    GOAL_PROHIBITION: this reason code alone means no rewrite exists, full stop.
    """
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="payment_send",
        arguments={"iban": "DE89370400440532013000", "amount": 1250},
    )
    policy = PolicyView({"allowed_tools": ["payment_send", "payment_draft"]})
    assert safer_alternative(action, policy, reasons=["UNTRUSTED_ARGUMENT_ORIGIN"]) is None


def test_an_explicit_user_prohibition_is_never_rewritten():
    """Substituting a neighbouring action when the user forbade this one is disobedience,
    not mitigation. A prohibition must reach BLOCK."""
    action = CandidateAction(
        type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "a@b.example", "body": "hi"}
    )
    assert safer_alternative(action, POLICY, reasons=["GOAL_PROHIBITION"]) is None
