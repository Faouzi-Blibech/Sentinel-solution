"""Decoding variants mirroring the evaluator's leak detector, then going beyond it.

The evaluator normalizes plain, url, base64, hex, rot13 and reversed text and strips
every non-alphanumeric character. Its own docstring calls it "not a general-purpose
exfiltration detector", so matching it is the floor, not the goal.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from urllib.parse import unquote

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
MAX_SCAN_CHARS = 200_000


def normalize(text: str) -> str:
    """Lowercase and drop every non-alphanumeric character.

    This defeats spaced-out, dotted and dashed exfiltration in a single step.
    """
    return _NON_ALNUM.sub("", text.lower())


def _decode_b64(text: str) -> str:
    out: list[str] = []
    for token in _B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            out.append(base64.b64decode(padded, validate=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(out)


def _decode_hex(text: str) -> str:
    out: list[str] = []
    for token in _HEX_TOKEN.findall(text):
        try:
            out.append(bytes.fromhex(token).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return "\n".join(out)


def reveals_any(text: str, needles: set[str]) -> str:
    """The first tainted value any decoding of `text` reveals, or "" if none does.

    The detector and the rewrite both ask this question, and they must agree. They did
    not: detection decoded base64/hex/rot13/reversed while the rewrite checked only the
    plain text, so a rewrite could strip the plain token, forward its base64 copy, and
    call the result clean. Needles are tried in sorted order so the answer never depends
    on set iteration order, which varies with PYTHONHASHSEED.
    """
    if not needles or not text:
        return ""
    ordered = sorted(n for n in needles if n)
    for _, decoded in variants(text):
        haystack = normalize(decoded)
        for needle in ordered:
            if needle in haystack:
                return needle
    return ""


def variants(text: str) -> list[tuple[str, str]]:
    """Return (encoding_name, decoded_text) pairs to scan for tainted values."""
    text = text[:MAX_SCAN_CHARS]
    return [
        ("plain", text),
        ("url", unquote(text)),
        ("base64", _decode_b64(text)),
        ("hex", _decode_hex(text)),
        ("rot13", codecs.decode(text, "rot13")),
        ("reversed", text[::-1]),
    ]
