"""Value-level taint.

We never see the evaluator's canary registry, so sensitive values must be derived
from what the agent observed rather than looked up. Deriving them is also what keeps
this free of scenario hard-coding and able to generalize to values we have not seen.
"""

from __future__ import annotations

import re

from sentinel.core.provenance import Sensitivity

from haris.encodings import normalize
from haris.trust import TrustView

MIN_TOKEN_CHARS = 8

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-/+]{6,}")
_HAS_DIGIT = re.compile(r"\d")
_ALL_ALPHA_WORD = re.compile(r"^[A-Za-z]+$")
_SHOUTED = re.compile(r"^[A-Z0-9]{8,}$")


def _is_identifier_like(token: str) -> bool:
    """Shaped like a secret rather than like prose."""
    # Trailing punctuation is the sentence's, not the token's.
    token = token.strip("._-/+")
    if len(normalize(token)) < MIN_TOKEN_CHARS:
        return False
    # A long unbroken run of capitals is a key or a phrase, not a sentence.
    if _SHOUTED.match(token):
        return True
    if _ALL_ALPHA_WORD.match(token):
        return False
    return bool(_HAS_DIGIT.search(token))


def extract_tainted_values(view: TrustView, minimum: Sensitivity = Sensitivity.CONFIDENTIAL) -> set[str]:
    """Normalized tokens that must not reach an untrusted destination.

    Requiring a digit silently switched the whole data-flow defense off for alphabetic
    secrets: a recovery phrase or an all-letter access key was never tainted, so it
    could be emailed anywhere. Shape is what separates a secret from prose, and an
    unbroken run of capitals is shape -- prose does not shout for sixteen characters.

    Known boundary, recorded rather than papered over: an all-lowercase passphrase made
    of dictionary words is indistinguishable from prose without a wordlist, and a
    wordlist is the keyword matching this defense exists to avoid. Such a value is not
    tainted here. The confirmation gate and the authority rule still govern the action
    that would carry it.
    """
    tainted: set[str] = set()
    for span in view.sensitive_spans(minimum):
        for match in _TOKEN.findall(span):
            if _is_identifier_like(match):
                tainted.add(normalize(match))
    return tainted
