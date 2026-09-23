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


def _clean(request):
    signals, _ = assess_dataflow(request, TrustView(request), POLICY)
    assert all(s.value == 0 for s in signals if s.code == SENSITIVE_TO_EXTERNAL_SINK)

SECRET = "CTR-SYN-906FAF7F88"
POLICY = PolicyView({"internal_email_domains": ["atlas.example"], "allowed_tools": ["email_send"]})

# 20 normalized chars, 10 letters + 10 digits, letter/digit strictly alternating so no
# 10-char window is ever single-class (I2) -- long and mixed enough to be
# "secret-shaped" per haris.encodings' fragmentable rule. SECRET above is only 16
# normalized chars, too short to fragment, so the fragment tests need their own needle.
FRAG_SECRET = "C1T2-R3S4-Y5N6-A7B8-C9D0"


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


# --- I2: a fragment window collides with ordinary prose once it is single-class ------
#
# The fragmentable predicate (>=20 chars, >=4 digits, >=4 letters) was judged on the
# WHOLE needle, but matching happens per 10-char window -- an all-letter or all-digit
# window of an otherwise mixed identifier collides with ordinary prose the instant
# normalize() strips its separators. Each probe below measured ALLOW -> BLOCK/REWRITE
# before `fragment_window_map` dropped single-class windows.


def test_all_letter_window_of_an_invoice_reference_does_not_collide_with_a_greeting():
    request = make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool",
                kind="tool_result",
                content="Invoice reference: ACME-Corp-Invoice-2026-0042.",
                provenance_ids=["p"],
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "partners@harbor-analytics.example", "body": "Hi ACME Corp, invoice received"},
        ),
    )
    _clean(request)


def test_all_letter_window_of_a_file_path_does_not_collide_with_its_own_description():
    request = make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.RESTRICTED)},
        conversation=[
            ConversationItem(
                role="tool",
                kind="tool_result",
                content="File: finance/2026/q3/revenue-summary-final-v2.xlsx",
                provenance_ids=["p"],
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={
                "to": "partners@harbor-analytics.example",
                "body": "The revenue summary was finalized last quarter.",
            },
        ),
    )
    _clean(request)


def test_all_letter_window_of_a_ticket_url_does_not_collide_with_a_vendor_name():
    request = make_request(
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool",
                kind="tool_result",
                content="Ticket: portal.vendorsupport.example/tickets/88213/case-notes-2026",
                provenance_ids=["p"],
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={
                "to": "partners@harbor-analytics.example",
                "body": "Please check the vendorsupport portal for updates.",
            },
        ),
    )
    _clean(request)


def test_shared_fragment_window_reports_every_parent_needle_not_just_one():
    # T3: two DIFFERENT needles that happen to share one 10-char window -- before this
    # fix, `fragment_window_map` attributed a shared window to whichever needle sorted
    # first (`setdefault`), so the OTHER needle's ownership of that exact window was
    # silently lost. Here the alphabetically-first needle is CONFIDENTIAL and the
    # second is RESTRICTED: a case note carrying only the shared window read ALLOW,
    # because the map had forgotten the restricted needle ever touched that window at
    # all. `fragment_hits` must return the union of every needle a window belongs to.
    shared = "a1b2c3d4e5"  # mixed, 10 chars -- survives I2's single-class window drop
    needle_confidential = shared + "y9y9y9y9y9"  # starts with 'a' -- sorts first
    needle_restricted = "zzzzzzzzzz" + shared  # starts with 'z' -- sorts second
    request = make_request(
        provenance={
            "conf": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL),
            "rest": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.RESTRICTED),
        },
        conversation=[
            ConversationItem(
                role="tool", kind="tool_result", content=f"Ref A: {needle_confidential}", provenance_ids=["conf"]
            ),
            ConversationItem(
                role="tool", kind="tool_result", content=f"Ref B: {needle_restricted}", provenance_ids=["rest"]
            ),
        ],
        action=CandidateAction(type=ActionType.RESPOND, content=f"Case note: reference {shared} recorded."),
    )
    signals, _ = assess_dataflow(request, TrustView(request), POLICY)
    assert any(s.code == SENSITIVE_TO_EXTERNAL_SINK and s.value > 0 for s in signals)


def test_fragment_window_named_by_the_user_does_not_count_as_a_restricted_copy():
    # A restricted record's hostname is also what the user's own goal names -- the
    # whole-needle "named_by_user" exemption already covers this for a full hit; I2
    # extends it to a fragment window too, since a fragment sharing only the user-named
    # portion is exactly as much theirs as the whole value would be.
    request = make_request(
        user_goal="Is db-prod-eu-west-01 in the inventory?",
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.RESTRICTED)},
        conversation=[
            ConversationItem(
                role="tool",
                kind="tool_result",
                content="Record: vault/db-prod-eu-west-01/root-token-2026",
                provenance_ids=["p"],
            )
        ],
        action=CandidateAction(
            type=ActionType.RESPOND, content="Yes, db-prod-eu-west-01 is in the inventory."
        ),
    )
    _clean(request)
