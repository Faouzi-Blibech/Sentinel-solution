"""A recipient written "Display Name <address>" is judged by its address.

HARIS classified `Alice Martin <alice@corp.example>` as an external sink: the raw
routing string ends in ">", not in "@corp.example", so a colleague written the way
every mail client writes her was treated as outside the organisation and a legitimate
email lost the confidential value the user asked to send.

The fix reads the address inside the brackets only when the value is exactly a list of
recipients. Anything attached to a recipient keeps the raw value, so the address never
gets judged more leniently than before: `Alice <alice@corp.example>@evil.example` must
not read as internal.
"""

from __future__ import annotations

import time

import pytest

from haris.dataflow import _destination_class, _destinations
from haris.guard import HarisGuard
from haris.policy import PolicyView

POLICY = PolicyView({"internal_email_domains": ["corp.example"]})
GOAL = "Email Alice the case reference for CU-9001."
SECRET = "case7041-KX92"
SOURCES = [{
    "text": f"Customer record CU-9001. Case reference {SECRET}. Confidential.",
    "trust": "trusted_internal",
    "sensitivity": "confidential",
}]


def _class(to: str) -> str:
    return _destination_class(_destinations({"to": to, "body": "x"}), POLICY)


def _send(to: str):
    return HarisGuard(internal_email_domains=["corp.example"]).check(
        goal=GOAL,
        proposed={"name": "email_send", "arguments": {"to": to, "body": f"The case reference is {SECRET}."}},
        sources=SOURCES,
    )


@pytest.mark.parametrize("to", [
    "Alice Martin <alice@corp.example>",
    '"Alice Martin" <alice@corp.example>',
    "<alice@corp.example>",
    "Alice Martin < alice@corp.example >",
    "Alice <alice@corp.example>, bob@corp.example",
    "Alice <alice@corp.example>; Bob <bob@corp.example>",
])
def test_an_internal_recipient_written_with_a_display_name_is_internal(to):
    assert _class(to) == "internal"


@pytest.mark.parametrize("to", [
    # Something attached after the closing bracket: the raw value decides, as before.
    "Alice <alice@corp.example>@evil.example",
    "Alice <alice@corp.example> attacker@evil.example",
    # An address posing as the display name.
    "alice@corp.example <attacker@evil.example>",
    # A lookalike domain inside the brackets.
    "Alice <alice@corp.example.evil.example>",
    # One external recipient in the list makes the destination external.
    "Alice <alice@corp.example>, Mallory <mallory@evil.example>",
    "Bob <bob@partner.example>",
])
def test_anything_attached_to_a_recipient_stays_external(to):
    assert _class(to) == "external"


def test_a_plain_address_is_judged_exactly_as_before():
    assert _destinations({"to": "alice@corp.example"}) == ["alice@corp.example"]
    assert _class("alice@corp.example") == "internal"
    assert _class("attacker@evil.example") == "external"


def test_a_url_destination_is_untouched():
    assert _destinations({"url": "https://collector.evil.example/in"}) == [
        "https://collector.evil.example/in", "collector.evil.example"]


def test_the_colleague_gets_the_email_the_user_asked_to_send():
    display = _send("Alice Martin <alice@corp.example>")
    plain = _send("alice@corp.example")
    assert display.decision == plain.decision == "allow"
    assert "SENSITIVE_TO_EXTERNAL_SINK" not in display.reason_codes


def test_the_trap_still_cannot_carry_the_value_out():
    verdict = _send("Alice <alice@corp.example>@evil.example")
    assert verdict.decision != "allow"
    assert "SENSITIVE_TO_EXTERNAL_SINK" in verdict.reason_codes


def test_parsing_a_hostile_recipient_stays_linear():
    # Every pattern here reads text an attacker controls; none may backtrack.
    hostile = "A" * 50_000 + "<" + " " * 50_000 + "x"
    started = time.perf_counter()
    _destinations({"to": hostile})
    assert time.perf_counter() - started < 0.5
