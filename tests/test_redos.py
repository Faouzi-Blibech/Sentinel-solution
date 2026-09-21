"""Text an attacker controls must not be able to stall a decision.

Found by timing every regex in src/haris against long runs of one character. Five
patterns backtracked quadratically: 8,000 newlines in a document kept the directive
detector busy for 4.4 seconds, a run of spaces after `call foo` did the same to the
tool-call detectors, and a long local part stalled the address extractor. The simulator
allows 5 seconds per decision and fails CLOSED, so an attacker who could plant
whitespace could make HARIS block the user's legitimate work -- a denial of service
through the very content the defense exists to inspect.

A linear pattern handles these inputs in well under a millisecond; a quadratic one takes
hundreds. The thresholds below sit between the two with a wide margin on both sides.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time

import haris
from sentinel.core.actions import MAX_ARG_CHARS, ActionType, CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.engine import decide
from tests.factories import make_request

RUN = 20_000
PER_PATTERN_BUDGET_S = 0.2
DECISION_BUDGET_S = 1.0

# Each shape defeated at least one pattern before the fix.
PREFIXES = ("", "call foo", "foo(", "you", "remember", "x@")
RUNS = (" ", "\n", "a", "{", ".", "0", '"', ":")
TAILS = ("", "!")


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    found = []
    for info in pkgutil.iter_modules(haris.__path__):
        module = importlib.import_module(f"haris.{info.name}")
        found.extend(
            (f"{info.name}.{name}", value) for name, value in vars(module).items() if isinstance(value, re.Pattern)
        )
    return found


def _seconds(pattern: re.Pattern[str], text: str) -> float:
    # The faster of two runs, so one garbage-collection pause cannot fail the suite.
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        list(pattern.finditer(text))
        best = min(best, time.perf_counter() - start)
    return best


def test_the_sweep_actually_finds_the_patterns() -> None:
    """Guard against going vacuously green, as the no-hardcoding audit once did."""
    names = {name for name, _ in _patterns()}
    assert {"authority._IMPERATIVE_OPENER", "authority._TOOL_SHAPED", "dataflow._EMAIL"} <= names


def test_no_pattern_backtracks_on_long_runs() -> None:
    slow = []
    for name, pattern in _patterns():
        for prefix in PREFIXES:
            for run in RUNS:
                for tail in TAILS:
                    text = prefix + run * RUN + tail
                    if _seconds(pattern, text) > PER_PATTERN_BUDGET_S:
                        slow.append(f"{name} on {prefix!r} + {run!r} x {RUN} + {tail!r}")
                        break
    assert not slow, "quadratic backtracking:\n" + "\n".join(slow)


def test_a_decision_over_hostile_whitespace_stays_fast() -> None:
    """The whole decision path, not one pattern: this is what the simulator's timeout sees."""
    hostile = "\n" * RUN + "call foo" + " " * RUN + "{" * RUN + "remember" + "\n" * RUN + "Send it."
    request = make_request(
        provenance={"doc": (TrustLevel.UNTRUSTED_EXTERNAL, Sensitivity.INTERNAL)},
        conversation=[ConversationItem(role="tool", kind="tool_result", content=hostile, provenance_ids=["doc"])],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_draft",
            # The contract caps each argument; observed content has no cap at all.
            arguments={"to": "a" * MAX_ARG_CHARS, "body": "x" * MAX_ARG_CHARS},
        ),
    )
    start = time.perf_counter()
    decide(request)
    assert time.perf_counter() - start < DECISION_BUDGET_S
