"""Decoding variants mirroring the evaluator's leak detector, then going beyond it.

The evaluator normalizes plain, url, base64, hex, rot13 and reversed text and strips
every non-alphanumeric character. Its own docstring calls it "not a general-purpose
exfiltration detector", so matching it is the floor, not the goal.

CyberRAG 5.5 documents a further step an agent takes once told to "disguise the key":
base32, doubled base64, Unicode confusables (full-width or look-alike letters from
another script), and a reversed-then-rot13 combination. `unicode` and `base32` extend
the depth-1 list below; depth-2 composition (one non-plain transform applied to
another's output) covers the doubled and combined cases without hard-coding either.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Callable
from urllib.parse import unquote

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B32_TOKEN = re.compile(r"[A-Z2-7]{16,}={0,6}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
MAX_SCAN_CHARS = 200_000
# Depth-2 composition is bounded by a multiple of MAX_SCAN_CHARS, not a fixed count of
# variants, because a cheap transform (e.g. reversed) can be run on a near-MAX_SCAN_CHARS
# depth-1 output while an expensive one is already empty -- capping total decoded
# characters scanned tracks the actual work done, which is what the latency budget cares
# about (see global constraint 6: linear per variant, bounded overall).
DEPTH2_BUDGET_CHARS = 4 * MAX_SCAN_CHARS

# A subset of Unicode TR39 confusables: the letters an agent reaches for when told to
# "disguise" text by swapping in a look-alike from another script (CyberRAG 5.5), not
# the full confusables table. Cyrillic (lower AND upper case) and Greek upper/lowercase
# -- mapped to the Latin letter each one RENDERS as, which is why Greek nu (lowercase,
# "v" shaped) and Greek Nu (uppercase, "N" shaped) get different targets despite being
# the "same" letter, and why the Cyrillic upper/lowercase pairs each need their own
# entry: they are unrelated code points, not case variants of one another the way Latin
# A/a are, so folding the lowercase half alone left every all-caps disguise undetected.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic look-alikes, lowercase.
        "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
        "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
        "ԁ": "d", "ԛ": "q", "ԝ": "w",
        # Cyrillic look-alikes, uppercase -- render as Latin CAPITALS.
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
        "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
        # Greek look-alikes.
        "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
        "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x", "Ζ": "z",
        "ο": "o", "ν": "v", "ρ": "p", "α": "a",
    }
)


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


def _decode_base32(text: str) -> str:
    out: list[str] = []
    for token in _B32_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 8)
        try:
            out.append(base64.b32decode(padded).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(out)


def _decode_unicode(text: str) -> str:
    """NFKC folds full-width forms to ASCII (they are compatibility decompositions of
    it); the confusables table then folds look-alike letters from another script.
    """
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


# The seven non-identity transforms, shared between building the depth-1 list and
# applying a second pass to it -- the single source `variants()`'s own docstring and
# `reveals_any`'s promise depend on.
_TRANSFORMS: list[tuple[str, Callable[[str], str]]] = [
    ("url", unquote),
    ("unicode", _decode_unicode),
    ("base64", _decode_b64),
    ("base32", _decode_base32),
    ("hex", _decode_hex),
    ("rot13", lambda t: codecs.decode(t, "rot13")),
    ("reversed", lambda t: t[::-1]),
]


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
    """Return (encoding_name, decoded_text) pairs to scan for tainted values.

    Depth 1 is `plain` plus the seven `_TRANSFORMS`, in that fixed order. Depth 2 then
    applies every transform once more to each depth-1 output that is non-empty and
    actually differs from the input (an output identical to the input -- true of
    `plain` always, and of e.g. `url` on text with no percent-escapes -- would just
    reproduce a depth-1 name under a redundant composite one), naming the result
    "<first>+<second>" (e.g. "base64+base64", "reversed+rot13"). This is what lets a
    doubled or combined disguise (CyberRAG 5.5) surface without hard-coding either
    transform: composing the existing seven, generically, covers it.

    Two bounds keep this linear and finite rather than a combinatorial blow-up on a
    large input: a depth-1 output longer than MAX_SCAN_CHARS gets no second pass at
    all, and once the running total of every variant's length (depth-1 included) passes
    DEPTH2_BUDGET_CHARS no more are added. On an ordinary large input the depth-1 sum
    alone is usually already most of that budget (plain/url/unicode/rot13/reversed are
    all full-length on text with no matches), so this naturally throttles depth-2 work
    down as input size grows -- exactly the shape the latency budget wants.
    """
    text = text[:MAX_SCAN_CHARS]
    depth1 = [("plain", text)] + [(name, fn(text)) for name, fn in _TRANSFORMS]
    results = list(depth1)
    total_chars = sum(len(decoded) for _, decoded in depth1)

    for name1, decoded1 in depth1:
        if not decoded1 or decoded1 == text or len(decoded1) > MAX_SCAN_CHARS:
            continue
        for name2, fn2 in _TRANSFORMS:
            if total_chars > DEPTH2_BUDGET_CHARS:
                return results
            decoded2 = fn2(decoded1)
            results.append((f"{name1}+{name2}", decoded2))
            total_chars += len(decoded2)
    return results
