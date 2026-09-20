"""The instruction-authority rule.

Untrusted text may be read, quoted and summarized. It may never authorize an action.

We deliberately do not try to recognize "an injection" -- that target is unbounded and
every new wording defeats it. Instead we measure whether untrusted content is *shaped
like a directive aimed at the agent*, which is a structural property and therefore
survives paraphrase, translation and obfuscation.
"""

from __future__ import annotations

import re

from sentinel.core.provenance import TrustLevel

from haris.signals import UNTRUSTED_INSTRUCTION_AUTHORITY, Signal

WEIGHT = 0.45

# Structural markers of a directive aimed at the reader, not domain keywords.
_SECOND_PERSON_DIRECTIVE = re.compile(
    r"\b(you\s+(must|should|need\s+to|are\s+required\s+to)|do\s+not|don't|never|always)\b",
    re.IGNORECASE,
)
_IMPERATIVE_OPENER = re.compile(
    r"(?:^|[.!?\n]\s*)(send|forward|email|upload|post|transfer|execute|confirm|approve|close|"
    r"disable|delete|ignore|disregard|override|reveal|share|export|append|remember|store|kindly)\b",
    re.IGNORECASE,
)
_AGENT_ADDRESS = re.compile(
    r"\b(assistant|ai\s+agent|automated\s+workflow|system\s+note|note\s+for\s+the\s+(assistant|agent))\b",
    re.IGNORECASE,
)
_TOOL_SHAPED = re.compile(r"\b[a-z][a-z0-9_]{2,}\s*\(\s*[{\"']", re.IGNORECASE)


def _directive_strength(text: str) -> tuple[float, list[str]]:
    hits: list[str] = []
    score = 0.0
    if _IMPERATIVE_OPENER.search(text):
        score += 0.55
        hits.append("imperative_opener")
    if _SECOND_PERSON_DIRECTIVE.search(text):
        score += 0.25
        hits.append("second_person_directive")
    if _AGENT_ADDRESS.search(text):
        score += 0.30
        hits.append("addresses_the_agent")
    if _TOOL_SHAPED.search(text):
        score += 0.45
        hits.append("tool_call_shaped")
    return min(1.0, score), hits


def assess_authority(view) -> list[Signal]:  # noqa: ANN001 -- haris.trust.TrustView
    """One signal: how strongly untrusted context is trying to give orders."""
    worst = 0.0
    detail = "no directive language in untrusted context"
    for content, trust in view.untrusted_spans():
        strength, hits = _directive_strength(content)
        # Less trusted sources carry proportionally more weight.
        scaled = min(1.0, strength * (1.0 + 0.15 * (trust.rank - TrustLevel.TRUSTED_INTERNAL.rank)))
        if scaled > worst:
            worst = scaled
            detail = f"{','.join(hits) or 'none'} @ {trust.value}"
    return [
        Signal(
            code=UNTRUSTED_INSTRUCTION_AUTHORITY,
            weight=WEIGHT,
            value=round(worst, 4),
            detail=detail,
        )
    ]
