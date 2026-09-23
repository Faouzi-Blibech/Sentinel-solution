import base64

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.dataflow import assess_dataflow
from haris.encodings import normalize
from haris.policy import PolicyView
from haris.signals import ENCODED_PAYLOAD_DETECTED, SENSITIVE_TO_EXTERNAL_SINK
from haris.trust import TrustView
from tests.factories import make_request

SECRET = "CTR-SYN-906FAF7F88"
POLICY = PolicyView({"internal_email_domains": ["atlas.example"], "allowed_tools": ["email_send"]})

# 20 normalized chars, 11 letters + 9 digits -- long and mixed enough to be
# "secret-shaped" per haris.encodings' fragmentable rule. SECRET above is only 16
# normalized chars, too short to fragment, so the fragment tests need their own needle.
FRAG_SECRET = "CTR-SYN-ABCDE123456789"


def _request(action: CandidateAction):
    return make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(role="tool", kind="tool_result", content=f"reference {SECRET}", provenance_ids=["p"])
        ],
        action=action,
    )


def _frag_request(action: CandidateAction):
    return make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool", kind="tool_result", content=f"reference {FRAG_SECRET}", provenance_ids=["p"]
            )
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


# --- Task 3: a fragment hit reports "fragment" in plain text, its own encoding elsewhere ---


def test_fragment_hit_in_plain_text_is_encoding_fragment_not_encoded_payload():
    normalized = normalize(FRAG_SECRET)
    half = normalized[:10]  # one clean 10-char window of a 20-char secret
    request = _frag_request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": f"ref {half}"},
        )
    )
    signals, meta = assess_dataflow(request, TrustView(request), POLICY)
    assert meta["encoding"] == "fragment"
    assert any(s.code == SENSITIVE_TO_EXTERNAL_SINK and s.value > 0 for s in signals)
    # R1: a plain-text fragment is a leak, but not an obfuscation -- it must not trip
    # the encoded-payload signal the way a base64/hex/rot13 hit does.
    assert all(s.value == 0 for s in signals if s.code == ENCODED_PAYLOAD_DETECTED)


def test_fragment_hit_inside_a_decoded_variant_keeps_that_variants_name():
    normalized = normalize(FRAG_SECRET)
    half = normalized[:10]
    # The whole payload reversed puts `half` back in forward order once the "reversed"
    # variant undoes it -- a fragment that only ever surfaces through a real decoding,
    # never in the plain text itself.
    request = _frag_request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": f"ref {half}"[::-1]},
        )
    )
    signals, meta = assess_dataflow(request, TrustView(request), POLICY)
    assert meta["encoding"] == "reversed"
    assert any(s.code == ENCODED_PAYLOAD_DETECTED and s.value > 0 for s in signals)


def test_full_needle_hit_in_plain_text_is_not_downgraded_to_fragment():
    # The whole secret is present, not just a window of it -- the encoding must read
    # "plain", the real hit, never "fragment".
    request = _frag_request(
        CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": f"ref {FRAG_SECRET}"},
        )
    )
    signals, meta = assess_dataflow(request, TrustView(request), POLICY)
    assert meta["encoding"] == "plain"
