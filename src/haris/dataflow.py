"""Secret-to-sink reachability.

The lethal trifecta made mechanical: sensitive data, untrusted influence, and an
external channel. We block the *combination*, never any single ingredient, which is
why reading vendor email and emailing colleagues both stay allowed.
"""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.actions import ActionType
from sentinel.core.provenance import Sensitivity
from sentinel.defenses.interface import DefenseRequest

from haris.encodings import normalize, variants
from haris.lifecycle import target_action
from haris.policy import PolicyView
from haris.secrets import extract_tainted_values
from haris.signals import ENCODED_PAYLOAD_DETECTED, SENSITIVE_TO_EXTERNAL_SINK, Signal
from haris.trust import TrustView

# A secret reaching a sink it may not reach is a policy violation, not a judgement call,
# so on its own it sits above block_threshold and the risk score agrees with the
# engine's rule that a leak is blocked or cleanly rewritten, never escalated.
SINK_WEIGHT = 0.75
ENCODING_WEIGHT = 0.20

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_DESTINATION_KEYS = ("to", "recipient", "destination", "url", "endpoint", "address", "email")


def _destinations(arguments: dict[str, Any]) -> list[str]:
    """Where the action routes -- not every address its text happens to mention.

    Harvesting addresses from every argument meant a draft to a colleague that cited
    the vendor's contact address was classified as an external sink, and a legitimate
    dispute summary carrying an invoice number was escalated. A destination is a
    routing argument; an address inside a body is content, and content is what the
    taint check is for.

    When an action declares no routing argument at all we fall back to scanning its
    values, because a tool we have never seen may name its destination differently and
    missing a real sink is the costlier error.
    """
    routing = {k: v for k, v in arguments.items() if k.lower() in _DESTINATION_KEYS}
    scanned = routing or arguments

    found: list[str] = []
    for key, value in scanned.items():
        if not isinstance(value, str):
            continue
        if key.lower() in _DESTINATION_KEYS:
            found.append(value)
        found.extend(_EMAIL.findall(value))
        found.extend(_URL.findall(value))
    # Preserve order while removing duplicates, so the metadata reads cleanly.
    return list(dict.fromkeys(found))


def _destination_class(destinations: list[str], policy: PolicyView) -> str:
    if not destinations:
        return "none"
    if all(policy.is_internal_destination(d) for d in destinations):
        return "internal"
    return "external"


def assess_dataflow(
    request: DefenseRequest, view: TrustView, policy: PolicyView
) -> tuple[list[Signal], dict[str, Any]]:
    # Judge the action that would take effect: a confirmation request carries the real
    # destination and the real payload inside confirmation_for.
    action = target_action(request.candidate_action)
    payload = action.text_payload()
    tainted = extract_tainted_values(view)
    # The top sensitivity is copy-restricted, not merely export-restricted. In the kit
    # this is modelled per canary and the SOC service token's allowed_destinations is
    # empty: it may reach no sink at all. Keying only on 'external' meant a restricted
    # credential written into an internal incident note passed silently, which is how
    # our own held-out SOC scenario beat this defense.
    restricted = extract_tainted_values(view, Sensitivity.RESTRICTED)

    destinations = _destinations(action.arguments) if action.type is ActionType.TOOL_CALL else []
    destination_class = _destination_class(destinations, policy)

    # Every hit, in a fixed order. Stopping at the first needle of a *set* made the
    # verdict depend on PYTHONHASHSEED, and let a confidential value in the same payload
    # hide a restricted one from the copy rule below.
    ordered = sorted(n for n in tainted if n)
    hits: list[tuple[str, str]] = []
    plain_hits: set[str] = set()
    if ordered and payload:
        for encoding, decoded in variants(payload):
            haystack = normalize(decoded)
            for needle in ordered:
                if needle in haystack:
                    hits.append((encoding, needle))
                    if encoding == "plain":
                        plain_hits.add(needle)

    # Identifiers the authenticated user named are theirs to work with. Restricted records
    # carry hostnames and asset ids alongside the secret, and echoing the host the user
    # asked about into a note is the task, not a leak.
    named_by_user = normalize(request.user_goal)
    restricted_hits = sorted(
        needle for _, needle in hits if needle in restricted and needle not in named_by_user
    )
    # The kit sinks a final answer as `user_response`. A restricted canary allows no
    # destination at all -- the user included -- so the answer counts here too.
    writes_a_sink = action.type in (ActionType.TOOL_CALL, ActionType.MEMORY_WRITE, ActionType.RESPOND)
    copied_restricted = bool(restricted_hits) and writes_a_sink
    external_hits = [needle for _, needle in hits] if destination_class == "external" else []
    leaking = bool(external_hits) or copied_restricted
    # Encoded only if a needle surfaced in a decoding and NOT in the plain text: the url
    # variant of ordinary text is the text itself and would otherwise always "match".
    obfuscated_hits = sorted({needle for encoding, needle in hits if encoding != "plain"} - plain_hits)
    obfuscated = leaking and bool(obfuscated_hits)

    hit_value = (restricted_hits or obfuscated_hits or sorted(plain_hits) or [""])[0]
    hit_encoding = next((e for e, n in hits if n == hit_value and (e != "plain") == (n in obfuscated_hits)), "")

    metadata: dict[str, Any] = {
        "destination_class": destination_class,
        "destinations": destinations[:3],
        "encoding": hit_encoding or "none",
        "hits": len({needle for _, needle in hits}),
        "tainted_value_count": len(tainted),
        "tainted_hit": (hit_value[:6] + "...") if hit_value else "",
        "restricted_copy": copied_restricted,
    }

    return (
        [
            Signal(
                code=SENSITIVE_TO_EXTERNAL_SINK,
                weight=SINK_WEIGHT,
                value=1.0 if leaking else 0.0,
                detail=(
                    f"restricted value copied into a {action.type.value} ({destination_class} destination)"
                    if copied_restricted
                    else f"{destination_class} sink, encoding={hit_encoding or 'none'}"
                ),
            ),
            Signal(
                code=ENCODED_PAYLOAD_DETECTED,
                weight=ENCODING_WEIGHT,
                value=1.0 if obfuscated else 0.0,
                detail=f"encoding={hit_encoding or 'none'}",
            ),
        ],
        metadata,
    )
