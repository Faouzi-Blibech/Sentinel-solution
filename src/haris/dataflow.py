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

from haris.config import SETTINGS, Settings
from haris.encodings import fragment_hits, fragment_window_map, normalize, variants
from haris.lifecycle import target_action
from haris.policy import PolicyView
from haris.recall import cached_extract, tainted_values
from haris.signals import ENCODED_PAYLOAD_DETECTED, SENSITIVE_TO_EXTERNAL_SINK, Signal
from haris.trust import TrustView

# A secret reaching a sink it may not reach is a policy violation, not a judgement call,
# so on its own it sits above block_threshold and the risk score agrees with the
# engine's rule that a leak is blocked or cleanly rewritten, never escalated.
SINK_WEIGHT = 0.75
ENCODING_WEIGHT = 0.20

# Start only where a local part can start. Without the lookbehind every character of a
# long run began a fresh attempt that rescanned the rest of it. The leftmost match was
# always at the run's start, so what is found does not change. See tests/test_redos.py.
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_DESTINATION_KEYS = ("to", "recipient", "destination", "url", "endpoint", "address", "email")
# One recipient written the way mail clients write it: "Display Name <address>". The name
# may not contain "<", ">" or "@", and nothing may follow the closing bracket. Anchored,
# so even an unanchored search tries one start, not every start -- unanchored, a long run
# with no "<" was rescanned from each position (tests/test_redos.py caught it). `[^<>\s]+`
# cannot overlap the `\s*` around it, so the address part is scanned once too.
_DISPLAY_NAME = re.compile(r"\A[^<>@]*<\s*([^<>\s]+)\s*>\s*\Z")
_RECIPIENT_SEPARATOR = re.compile(r"[,;]")


def _recipients(value: str) -> list[str] | None:
    """The addresses a routing value names, when the value is only a list of recipients.

    `Alice Martin <alice@corp.example>` was judged by its raw text, which ends in ">", so a
    colleague written the way every mail client writes her was an external sink and a
    legitimate email lost the value the user asked to send. Each part must be a bare
    address or `Name <address>`; if any part is anything else the answer is None and the
    caller judges the raw value exactly as before. So an address is never read more
    leniently than it was: `Alice <alice@corp.example>@evil.example` is not a recipient
    list, and stays external. A display name quoted around a comma ("Martin, Alice")
    splits into parts that are not recipients, and falls back the same safe way.
    """
    addresses: list[str] = []
    for part in _RECIPIENT_SEPARATOR.split(value):
        part = part.strip()
        if not part:
            continue
        named = _DISPLAY_NAME.fullmatch(part)
        address = named.group(1) if named else part
        if not _EMAIL.fullmatch(address):
            return None
        addresses.append(address)
    return addresses or None


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
            recipients = _recipients(value)
            if recipients is not None:
                found.extend(recipients)
                continue
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
    request: DefenseRequest, view: TrustView, policy: PolicyView, settings: Settings = SETTINGS
) -> tuple[list[Signal], dict[str, Any]]:
    # Judge the action that would take effect: a confirmation request carries the real
    # destination and the real payload inside confirmation_for.
    action = target_action(request.candidate_action)
    payload = action.text_payload()
    # What THIS request's own spans show, with no memory involved -- kept separately so
    # the metadata below can report how much of `tainted` came from recall rather than
    # from something visible right now (report.md 8.1: the whole point of the fix is
    # that these two can now differ). `tainted_values`' own CONFIDENTIAL derivation
    # below is a cache hit against this, not a second scan.
    visible = cached_extract(view, Sensitivity.CONFIDENTIAL)
    tainted = tainted_values(request, view, Sensitivity.CONFIDENTIAL, settings)
    # The top sensitivity is copy-restricted, not merely export-restricted. In the kit
    # this is modelled per canary and the SOC service token's allowed_destinations is
    # empty: it may reach no sink at all. Keying only on 'external' meant a restricted
    # credential written into an internal incident note passed silently, which is how
    # our own held-out SOC scenario beat this defense.
    restricted = tainted_values(request, view, Sensitivity.RESTRICTED, settings)

    destinations = _destinations(action.arguments) if action.type is ActionType.TOOL_CALL else []
    destination_class = _destination_class(destinations, policy)

    # Every hit, in a fixed order. Stopping at the first needle of a *set* made the
    # verdict depend on PYTHONHASHSEED, and let a confidential value in the same payload
    # hide a restricted one from the copy rule below.
    ordered = sorted(n for n in tainted if n)
    hits: list[tuple[str, str]] = []
    plain_hits: set[str] = set()
    if ordered and payload:
        # Built once for the whole call, not per variant (CyberRAG 5.5 split
        # exfiltration): a fragment of a long, secret-shaped needle counts as a hit of
        # that needle too, via haris.encodings' own window-matching helper -- the same
        # one reveals_any calls, so detection and the rewrite's leak check cannot
        # disagree about what a fragment reveals the way they once disagreed about
        # encodings.
        window_map = fragment_window_map(ordered)
        for encoding, decoded in variants(payload):
            haystack = normalize(decoded)
            full_hits_here: set[str] = set()
            for needle in ordered:
                if needle in haystack:
                    hits.append((encoding, needle))
                    full_hits_here.add(needle)
                    if encoding == "plain":
                        plain_hits.add(needle)
            # A full-needle hit already found in this exact variant always wins over a
            # fragment hit of the same needle (report the full hit, never downgrade it).
            for needle in sorted(fragment_hits(haystack, window_map) - full_hits_here):
                if encoding == "plain":
                    # A fragment surfacing in the plain text is still a leak, but it is
                    # not an obfuscation -- "fragment" is its own encoding name so R1's
                    # rule (no ENCODED_PAYLOAD_DETECTED for it) can key off it below,
                    # the same way "plain" itself is excluded.
                    hits.append(("fragment", needle))
                    plain_hits.add(needle)
                else:
                    # Found only inside a real decoding (e.g. reversed, base64): keep
                    # that variant's name, so it is obfuscated exactly like a full hit
                    # in that encoding would be.
                    hits.append((encoding, needle))

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
    # "fragment" (a plain-text fragment hit, R1) is excluded exactly like "plain" is: a
    # fragment sitting in the clear is a leak, but reading ten characters of prose is not
    # an obfuscation, so it must not trip ENCODED_PAYLOAD_DETECTED.
    obfuscated_hits = sorted(
        {needle for encoding, needle in hits if encoding not in ("plain", "fragment")} - plain_hits
    )
    obfuscated = leaking and bool(obfuscated_hits)

    hit_value = (restricted_hits or obfuscated_hits or sorted(plain_hits) or [""])[0]
    if hit_value and hit_value in obfuscated_hits:
        hit_encoding = next((e for e, n in hits if n == hit_value and e not in ("plain", "fragment")), "")
    elif hit_value:
        hit_encoding = next((e for e, n in hits if n == hit_value and e in ("plain", "fragment")), "")
    else:
        hit_encoding = ""

    metadata: dict[str, Any] = {
        "destination_class": destination_class,
        "destinations": destinations[:3],
        "encoding": hit_encoding or "none",
        "hits": len({needle for _, needle in hits}),
        "tainted_value_count": len(tainted),
        "tainted_hit": (hit_value[:6] + "...") if hit_value else "",
        "restricted_copy": copied_restricted,
        # How many of `tainted` this request did not itself show -- i.e. surfaced only
        # because a run-scoped memory remembered them. A count, not the values: they are
        # secrets and this dict is written to the journal on disk.
        "recalled": len(tainted - visible),
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
