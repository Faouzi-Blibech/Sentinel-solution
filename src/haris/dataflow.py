"""Secret-to-sink reachability.

The lethal trifecta made mechanical: sensitive data, untrusted influence, and an
external channel. We block the *combination*, never any single ingredient, which is
why reading vendor email and emailing colleagues both stay allowed.
"""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.actions import ActionType
from sentinel.defenses.interface import DefenseRequest

from haris.encodings import normalize, variants
from haris.policy import PolicyView
from haris.secrets import extract_tainted_values
from haris.signals import ENCODED_PAYLOAD_DETECTED, SENSITIVE_TO_EXTERNAL_SINK, Signal
from haris.trust import TrustView

SINK_WEIGHT = 0.60
ENCODING_WEIGHT = 0.20

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_DESTINATION_KEYS = ("to", "recipient", "destination", "url", "endpoint", "address", "email")


def _destinations(arguments: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for key, value in arguments.items():
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
    action = request.candidate_action
    payload = action.text_payload()
    tainted = extract_tainted_values(view)

    destinations = _destinations(action.arguments) if action.type is ActionType.TOOL_CALL else []
    destination_class = _destination_class(destinations, policy)

    hit_encoding = ""
    hit_value = ""
    if tainted and payload:
        for encoding, decoded in variants(payload):
            haystack = normalize(decoded)
            for needle in tainted:
                if needle and needle in haystack:
                    hit_encoding, hit_value = encoding, needle
                    break
            if hit_encoding:
                break

    leaking_externally = bool(hit_encoding) and destination_class == "external"
    obfuscated = bool(hit_encoding) and hit_encoding != "plain"

    metadata: dict[str, Any] = {
        "destination_class": destination_class,
        "destinations": destinations[:3],
        "encoding": hit_encoding or "none",
        "tainted_value_count": len(tainted),
        "tainted_hit": (hit_value[:6] + "...") if hit_value else "",
    }

    return (
        [
            Signal(
                code=SENSITIVE_TO_EXTERNAL_SINK,
                weight=SINK_WEIGHT,
                value=1.0 if leaking_externally else 0.0,
                detail=f"{destination_class} sink, encoding={hit_encoding or 'none'}",
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
