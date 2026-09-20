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


def _is_identifier_like(token: str) -> bool:
    """Identifiers, not prose: long, containing a digit, not an ordinary word."""
    if len(normalize(token)) < MIN_TOKEN_CHARS:
        return False
    if _ALL_ALPHA_WORD.match(token):
        return False
    return bool(_HAS_DIGIT.search(token))


def extract_tainted_values(view: TrustView, minimum: Sensitivity = Sensitivity.CONFIDENTIAL) -> set[str]:
    """Normalized tokens that must not reach an untrusted destination."""
    tainted: set[str] = set()
    for span in view.sensitive_spans(minimum):
        for match in _TOKEN.findall(span):
            if _is_identifier_like(match):
                tainted.add(normalize(match))
    return tainted
