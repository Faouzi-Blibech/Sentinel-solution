"""The instruction-authority rule.

Untrusted text may be read, quoted and summarized. It may never authorize an action.

We deliberately do not try to recognize "an injection" -- that target is unbounded and
every new wording defeats it. Instead we measure whether untrusted content is *shaped
like a directive aimed at the agent*, which is a structural property and therefore
survives paraphrase, translation and obfuscation.
"""

from __future__ import annotations

import re

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import TrustLevel

from haris.encodings import normalize
from haris.signals import UNTRUSTED_INSTRUCTION_AUTHORITY, UNTRUSTED_MEMORY_AUTHORITY, Signal

WEIGHT = 0.45
# Memory that the agent wrote after reading untrusted content is the spec's own named
# attack family. Acting on it is a provenance violation in its own right, so it carries
# more weight than a passing directive and reaches a human on its own.
MEMORY_WEIGHT = 0.55
# Directive text the agent is demonstrably not following still belongs in the trace, but
# must not escalate by itself: at this factor it lands well below escalate_threshold.
UNOBEYED_FACTOR = 0.35
# Short tokens collide with ordinary prose once non-alphanumerics are stripped.
MIN_CORRESPONDENCE_CHARS = 6

# Identifier-like fragments of an argument: tool names, addresses, record ids. Matching
# these against untrusted text is how we tell "text gave an order" from "the agent is
# carrying that order out".
_CORRESPONDENCE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+\-/@]{4,}")
_ALL_ALPHA = re.compile(r"^[A-Za-z]+$")

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
# A tool invocation written out in text, in either of the two shapes it takes: a call
# with a parenthesised argument block, or an imperative naming a tool and a JSON body.
# Only the first was matched before, which meant the most direct form of all -- the one
# the simulator's own agent acts on, `call <tool> with {json}` -- scored zero here.
_TOOL_SHAPED = re.compile(
    r"\b[a-z][a-z0-9_]{2,}\s*\(\s*[{\"']"
    r"|\b(?:call|invoke|run|execute|perform)\s+[a-z][a-z0-9_]{2,}\s*(?:with|using)?\s*[{\(]",
    re.IGNORECASE,
)
# Text instructing the agent to persist something is a directive even without a verb
# opener: it is how a poisoned memory gets planted for a later turn.
_MEMORY_DIRECTIVE = re.compile(r"(?:^|[.!?\n]\s*)(remember|note\s+to\s+self|store\s+this)\s*:", re.IGNORECASE)

# The same two tool-call shapes as _TOOL_SHAPED, capturing the tool named and stopping at
# the opening brace of the argument block the text dictates for it.
_DICTATED_CALL = re.compile(
    r"\b(?:call|invoke|run|execute|perform)\s+([a-z][a-z0-9_]{2,})\s*(?:(?:with|using)\s*)?(?=\{)"
    r"|\b([a-z][a-z0-9_]{2,})\s*\(\s*(?=\{)",
    re.IGNORECASE,
)
_DICTATED_VALUE = re.compile(r':\s*"((?:[^"\\]|\\.)*)"')
# `{{last_result}}` names a slot the agent fills, not a value the text supplies. No brace
# inside it: `.*?` let every "{{" of a brace run scan to the end of the text.
_PLACEHOLDER = re.compile(r"\{\{[^{}]*\}\}")
_WORD = re.compile(r"[a-z0-9]+")
# Long enough to skip "the", "and", "with"; short enough to keep "token" and "portal".
MIN_DICTATED_WORD = 5


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
    if _MEMORY_DIRECTIVE.search(text):
        score += 0.40
        hits.append("memory_directive")
    return min(1.0, score), hits


def _action_tokens(action: CandidateAction) -> set[str]:
    """Normalized things the action is about: its tool and its identifier-like values."""
    tokens = _argument_tokens(action)
    if action.tool and len(normalize(action.tool)) >= MIN_CORRESPONDENCE_CHARS:
        tokens.add(normalize(action.tool))
    return tokens


def _argument_tokens(action: CandidateAction) -> set[str]:
    """Normalized identifier-like values in the action's arguments.

    Ordinary words must stay out. An early version collected every word of a message
    body, so a draft mentioning a "delivery window" matched a vendor email mentioning
    the same delivery window and the courtesy was read as an obeyed order. Only tokens
    that identify something -- an address, a record id -- can show that this action and
    that text are about the same thing.
    """
    tokens: set[str] = set()
    for value in action.arguments.values():
        if not isinstance(value, str):
            continue
        for match in _CORRESPONDENCE_TOKEN.finditer(value):
            # Trailing punctuation is sentence structure, not identifier structure:
            # "window." survived the all-alpha test and matched a vendor's prose.
            raw = match.group(0).strip("._-/@")
            if _ALL_ALPHA.match(raw):
                continue
            token = normalize(raw)
            if len(token) >= MIN_CORRESPONDENCE_CHARS:
                tokens.add(token)
    return {t for t in tokens if len(t) >= MIN_CORRESPONDENCE_CHARS}


def _ungrounded(tokens: set[str], grounded: str) -> set[str]:
    """Drop parameters the user's own goal or trusted context already named."""
    haystack = normalize(grounded)
    return {token for token in tokens if token not in haystack}


def _is_obeyed(span: str, tokens: set[str]) -> str:
    """Does this untrusted span name what the agent is doing right now?

    Directive-shaped text is common in ordinary correspondence -- "please do not
    hesitate", "kindly share the delivery window", "you must retain this" -- and scoring
    it as an attempt to command the agent escalated plain summarise-and-draft work.
    What makes untrusted text dangerous is not that it gives orders but that the agent
    is carrying them out, so we look for the order and its execution together.
    """
    if not tokens:
        return ""
    haystack = normalize(span)
    for token in sorted(tokens, key=len, reverse=True):
        if token in haystack:
            return token
    return ""


def _argument_block(text: str, start: int) -> str:
    """The brace-balanced block opening at `start`, or the rest of the text if unclosed."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return text[start:]


def _obeys_dictated_call(span: str, action: CandidateAction, grounded_words: set[str]) -> str:
    """Is the agent making a call this span wrote out, with the arguments it dictated?

    A tool name alone proves nothing: the agent knows its tools from the policy, so a
    legitimate call to a tool an injection also named is not obedience. What only the
    injection can supply is the arguments it dictates. Those are often plain words -- a
    search query -- which `_argument_tokens` rightly ignores in free text; inside a call
    the text itself addressed to this tool, they are specific enough to count. A value
    counts as carried when two of its words (one, if it has only one) that the user's
    goal and trusted context never used turn up in this call, which survives the agent
    trimming or reordering the query.
    """
    if not action.tool:
        return ""
    carried = {
        word
        for value in action.arguments.values()
        if isinstance(value, str)
        for word in _WORD.findall(value.lower())
    }
    for match in _DICTATED_CALL.finditer(span):
        named = match.group(1) or match.group(2)
        if named.lower() != action.tool.lower():
            continue
        for value in _DICTATED_VALUE.findall(_argument_block(span, match.end())):
            words = {
                word
                for word in _WORD.findall(_PLACEHOLDER.sub(" ", value).lower())
                if len(word) >= MIN_DICTATED_WORD and word not in grounded_words
            }
            if words and len(words & carried) >= min(2, len(words)):
                return normalize(action.tool)
    return ""


def assess_authority(view, action: CandidateAction) -> list[Signal]:  # noqa: ANN001 -- TrustView
    """One signal: how strongly untrusted context is giving orders the agent is following."""
    grounded = view.grounded_text()
    tokens = _ungrounded(_argument_tokens(action), grounded)
    grounded_words = set(_WORD.findall(grounded.lower()))
    worst = 0.0
    detail = "no directive language in untrusted context"
    for content, trust in view.untrusted_spans():
        strength, hits = _directive_strength(content)
        if strength <= 0.0:
            continue
        # Less trusted sources carry proportionally more weight.
        scaled = min(1.0, strength * (1.0 + 0.15 * (trust.rank - TrustLevel.TRUSTED_INTERNAL.rank)))
        obeyed = _is_obeyed(content, tokens) or _obeys_dictated_call(content, action, grounded_words)
        # Text the agent is not acting on stays visible in the trace but cannot escalate
        # on its own. Text naming the address now in flight, or dictating the call now in
        # flight, counts in full.
        value = scaled if obeyed else scaled * UNOBEYED_FACTOR
        if value > worst:
            worst = value
            corroboration = f"acting on {obeyed!r}" if obeyed else "not reflected in this action"
            detail = f"{','.join(hits) or 'none'} @ {trust.value}, {corroboration}"
    return [
        Signal(
            code=UNTRUSTED_INSTRUCTION_AUTHORITY,
            weight=WEIGHT,
            value=round(worst, 4),
            detail=detail,
        )
    ]


def assess_memory_authority(
    view, action: CandidateAction, unauthorized: bool  # noqa: ANN001 -- TrustView
) -> list[Signal]:
    """Recalled memory is evidence. It is never a permission.

    "Memory inherits trust. An entry written after reading untrusted content stays
    untrusted when recalled later." We had no rule for this: a poisoned memory was
    caught, when it was caught, by a generic drift signal, and the reason code that
    names the actual problem fired for nothing.

    The test is the same structural one used for observed content: the memory carries
    no authority unless the action in flight is the thing that memory describes.
    """
    tokens = _ungrounded(_action_tokens(action), view.grounded_text())
    worst = 0.0
    detail = "no untrusted memory bears on this action"
    # Memory is allowed to carry facts. It becomes *authority* only when it is standing
    # in for a permission the goal and the policy did not give -- an agent recalling the
    # invoice id it is working on is doing its job, not being steered.
    for content, trust in view.memory_spans() if unauthorized else ():
        if trust.is_trusted:
            continue
        obeyed = _is_obeyed(content, tokens)
        if not obeyed:
            continue
        scaled = min(1.0, 1.0 + 0.15 * (trust.rank - TrustLevel.TRUSTED_INTERNAL.rank))
        if scaled > worst:
            worst = scaled
            detail = f"acting on {obeyed!r} recalled from {trust.value} memory"
    return [
        Signal(
            code=UNTRUSTED_MEMORY_AUTHORITY,
            weight=MEMORY_WEIGHT,
            value=round(worst, 4),
            detail=detail,
        )
    ]
