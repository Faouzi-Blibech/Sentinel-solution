"""Decoding variants mirroring the evaluator's leak detector, then going beyond it.

The evaluator normalizes plain, url, base64, hex, rot13 and reversed text and strips
every non-alphanumeric character. Its own docstring calls it "not a general-purpose
exfiltration detector", so matching it is the floor, not the goal.

CyberRAG §5.5 (FGCS 176 (2026) 108186) is an attack-classifier robustness benchmark: it
perturbs known-attack inputs with what it names generically as "character obfuscation,
encoding variations, or token reordering" and measures whether the classifier still
labels them correctly. It does not catalog concrete transforms, does not mention
base32, doubled base64, confusables, or splitting a value across calls, and runs no
red-team loop. base32, Unicode confusables (full-width or look-alike letters from
another script), doubled base64, and the reversed-then-rot13 combination below are OUR
instantiation of §5.5's three named categories -- encoding variation and character
obfuscation -- for the exfiltration-disguise problem HARIS actually faces, not a list
transcribed from the paper. `unicode` and `base32` extend the depth-1 list below;
depth-2 composition (one non-plain transform applied to another's output) covers the
doubled and combined cases without hard-coding either.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Callable, Iterable
from functools import lru_cache
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
# "disguise" text by swapping in a look-alike from another script -- our own
# instantiation of §5.5's "character obfuscation" category (CyberRAG names the
# category, not this specific technique), not the full confusables table. Cyrillic
# (lower AND upper case) and Greek upper/lowercase
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

    A decoding that reveals only a long-enough FRAGMENT of a needle (CyberRAG 5.5's
    split exfiltration: send half a secret per call) counts too -- see
    `fragment_window_map`/`fragment_hits` below, the same helper `dataflow.py`'s hit
    loop calls, so the two cannot disagree about what counts as a leak the way
    detection and rewrite once disagreed about encodings.
    """
    if not needles or not text:
        return ""
    ordered = sorted(n for n in needles if n)
    window_map = fragment_window_map(ordered)
    for _, decoded in variants(text):
        haystack = normalize(decoded)
        for needle in ordered:
            if needle in haystack:
                return needle
        hits = fragment_hits(haystack, window_map)
        if hits:
            return sorted(hits)[0]
    return ""


# --- Fragment matching (CyberRAG -- split exfiltration) -------------------------------

# A needle only counts as "secret-shaped" -- worth matching on a piece of it rather than
# the whole thing -- once it is both long and mixed: long enough that a random 10-char
# run of it is unlikely to collide with ordinary text, and mixing digits with letters so
# an ordinary prose identifier or hostname (long, but usually all-letters) is excluded.
# Mirrors secrets.py's own shape test for what counts as a secret in the first place.
FRAGMENTABLE_MIN_CHARS = 20
FRAGMENTABLE_MIN_DIGITS = 4
FRAGMENTABLE_MIN_LETTERS = 4

# Window length for fragment matching. Shorter windows catch a finer split -- an agent
# could halve a secret into pieces below this size and still slip through -- but cost
# precision: at W=10 any two needles that happen to share a common 10-char run collide,
# and a payload need only reproduce ten consecutive characters of a secret to be judged
# as carrying it. 10 is where we fix that trade-off.
FRAGMENT_WINDOW_CHARS = 10


def _is_fragmentable(needle: str) -> bool:
    """Every caller already hands this a normalized (lowercase, alnum-only) needle."""
    if len(needle) < FRAGMENTABLE_MIN_CHARS:
        return False
    if sum(1 for ch in needle if ch.isdigit()) < FRAGMENTABLE_MIN_DIGITS:
        return False
    return sum(1 for ch in needle if ch.isalpha()) >= FRAGMENTABLE_MIN_LETTERS


def fragment_window_map(needles: Iterable[str]) -> dict[str, frozenset[str]]:
    """Every length-`FRAGMENT_WINDOW_CHARS` substring of each fragmentable needle,
    mapped back to EVERY needle it came from (T3: two different needles can share one
    window verbatim; attributing it to only one silently drops the other's fragment).

    Meant to be built once per call site (`reveals_any` above, `dataflow.assess_dataflow`)
    and reused for every variant's haystack -- but `_redact`'s replace callback calls
    `reveals_any` once per matched token in the payload, which calls this function again
    each time. Without the cache below that meant hundreds of rebuilds of the same map
    per decision (measured: 741, on an 8,000-char body) -- the dominant cost in the I3
    latency finding. Callers still get a dict keyed however `needles` arrived; the cache
    lives in the sorted-tuple wrapper so it is transparent to every caller.
    """
    return _cached_fragment_window_map(tuple(sorted(n for n in needles if n)))


@lru_cache(maxsize=64)
def _cached_fragment_window_map(needles: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """`needles` arrives already deduplicated-by-sort from `fragment_window_map`, so the
    cache key is stable across callers that pass the same needle set in any order.
    Needles are walked in sorted order so a window's needle set is built the same way
    regardless of the input's own order -- not for a single-owner tie-break any more
    (T3: every parent needle is kept, so there is no tie to break), but so the cached
    dict is reproducibly identical for the same needle set.
    """
    window_map: dict[str, set[str]] = {}
    for needle in needles:
        if not _is_fragmentable(needle):
            continue
        for start in range(len(needle) - FRAGMENT_WINDOW_CHARS + 1):
            window = needle[start : start + FRAGMENT_WINDOW_CHARS]
            # I2: `_is_fragmentable` judges the WHOLE needle (mixed digits and letters
            # separates a secret from prose), but matching happens per window -- a
            # single-class 10-char window of an otherwise-mixed needle (an all-letter
            # run inside a file path, an all-digit run inside a reference number) is
            # itself indistinguishable from ordinary prose once normalize() strips
            # separators. secrets.py's own shape rule, applied here per window instead
            # of per needle.
            if window.isalpha() or window.isdigit():
                continue
            window_map.setdefault(window, set()).add(needle)
    return {window: frozenset(parents) for window, parents in window_map.items()}


def fragment_hits(haystack: str, window_map: dict[str, frozenset[str]]) -> set[str]:
    """Parent needles that any length-`FRAGMENT_WINDOW_CHARS` window of `haystack`
    reveals, per `window_map` (from `fragment_window_map`).

    The UNION of every window's parent needles (T3): a matching window can belong to
    more than one needle, and reporting only one would silently drop the others --
    exactly how a restricted value's fragment went unnoticed when it happened to share
    a window with a confidential one.

    Linear in `len(haystack)`: every window of the haystack is collected into a set
    once, then intersected against `window_map` -- never a substring search repeated
    per window, which is what a naive "for each window: window in haystack" would cost
    (it degrades to quadratic on a long payload).
    """
    if not window_map or len(haystack) < FRAGMENT_WINDOW_CHARS:
        return set()
    haystack_windows = {
        haystack[i : i + FRAGMENT_WINDOW_CHARS] for i in range(len(haystack) - FRAGMENT_WINDOW_CHARS + 1)
    }
    hits: set[str] = set()
    for window in haystack_windows:
        hits |= window_map.get(window, frozenset())
    return hits


def variants(text: str) -> list[tuple[str, str]]:
    """Return (encoding_name, decoded_text) pairs to scan for tainted values.

    Depth 1 is `plain` plus the seven `_TRANSFORMS`, in that fixed order. Depth 2 then
    applies every transform once more to each depth-1 output that is non-empty and
    actually differs from the input (an output identical to the input -- true of
    `plain` always, and of e.g. `url` on text with no percent-escapes -- would just
    reproduce a depth-1 name under a redundant composite one), naming the result
    "<first>+<second>" (e.g. "base64+base64", "rot13+reversed"). This is what lets a
    doubled or combined disguise (CyberRAG 5.5) surface without hard-coding either
    transform: composing the existing seven, generically, covers it.

    Every result is deduplicated by its DECODED TEXT, not its name: `url` and `unicode`
    both decode to the same plain text on an input with no percent-escapes and no
    confusables, and rot13 commutes with reversal so "rot13+reversed" and
    "reversed+rot13" land on the identical string. A duplicate would cost every caller
    (`reveals_any`, `dataflow.assess_dataflow`) a full normalize-and-search pass over the
    haystack for no new information -- most of the I3 latency finding was exactly this,
    multiplied by however many times `variants()` runs per decision. The FIRST name to
    produce a given decoded text keeps it (`plain` always wins its own text, since it is
    added first); later names that land on the same text are dropped entirely, not
    merely hidden -- they never reach the caller's scan.

    Two bounds keep this linear and finite rather than a combinatorial blow-up on a
    large input: a depth-1 output longer than MAX_SCAN_CHARS gets no second pass at
    all, and once the running total of every variant's length (depth-1 included, before
    dedup -- the transform still ran, so it still counts as work done) passes
    DEPTH2_BUDGET_CHARS no more are added. On an ordinary large input the depth-1 sum
    alone is usually already most of that budget (plain/url/unicode/rot13/reversed are
    all full-length on text with no matches), so this naturally throttles depth-2 work
    down as input size grows -- exactly the shape the latency budget wants.
    """
    text = text[:MAX_SCAN_CHARS]
    seen: set[str] = set()
    results: list[tuple[str, str]] = []

    def add(name: str, decoded: str) -> None:
        if decoded in seen:
            return
        seen.add(decoded)
        results.append((name, decoded))

    depth1 = [("plain", text)] + [(name, fn(text)) for name, fn in _TRANSFORMS]
    for name, decoded in depth1:
        add(name, decoded)
    total_chars = sum(len(decoded) for _, decoded in depth1)

    for name1, decoded1 in depth1:
        if not decoded1 or decoded1 == text or len(decoded1) > MAX_SCAN_CHARS:
            continue
        for name2, fn2 in _TRANSFORMS:
            if total_chars > DEPTH2_BUDGET_CHARS:
                return results
            decoded2 = fn2(decoded1)
            total_chars += len(decoded2)
            add(f"{name1}+{name2}", decoded2)
    return results
