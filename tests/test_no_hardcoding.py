"""The disqualification rule, enforced by the test suite instead of by discipline.

The specification book is unambiguous: *"Scenario-specific hard-coding is not a valid
defense. Deciding from a scenario identifier, a filename, or any organizer-provided
expected outcome disqualifies that decision, however correct it looks in the video."*

The design doc listed a lint rule as the mitigation for this risk and the lint rule was
never written, so the guarantee rested on nobody making a mistake. This file replaces
that with a check that runs on every commit.

Three things are verified:

1. No identifier the organizers invented -- a scenario id, a filename, an address, a
   synthetic domain, a record id -- appears anywhere in `src/haris/`. The check runs
   corpus-first: asking instead whether each of *our* literals occurs somewhere in the
   kit flags ordinary English ("execute", "status") and the contract field names we are
   required to read, none of which is hard-coding.
2. No module in `src/haris/` reads `run_id` or `step_id` AS A LABEL outside the journal,
   which records them after the decision is made and never feeds them back into it.
   `recall.py` is also exempt: it reads `run_id` only as an opaque key partitioning a
   bounded memory store, never as content the decision branches on -- see the comment
   at `RUN_SCOPED_MEMORY` below for the distinction this rule is actually drawing.
3. The extractor still matches the shapes it claims to. An audit that cannot fail is
   worse than no audit, and this one shipped broken once already: a word-boundary escape
   written through a shell heredoc became a literal backspace byte, so the pattern
   matched nothing and the suite went green on a vacuous check.

The kit is optional: when it is absent the corpus checks skip rather than fail, so the
suite still runs on a clean clone.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import sys

import pytest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src" / "haris"
# Identifiers short enough to collide with ordinary English are not evidence of copying.
MIN_LITERAL_CHARS = 6
# journal.py records run_id and step_id for the observability layer. That happens after
# decide() has returned, so it cannot influence a decision.
OBSERVABILITY_ONLY = {"journal.py"}
# recall.py partitions its bounded taint-memory store by run_id, using it purely as an
# opaque dictionary key: TaintMemory.remember/recall run the identical lookup and LRU
# logic no matter what run_id equals, and no branch of that module's behaviour depends
# on which run it is or what the string contains. That is different in kind from a
# scenario label reaching the decision AS CONTENT the decision branches on -- e.g.
# recognizing a particular run and deciding differently for it -- which is what this
# rule exists to catch (see the module docstring above). Correlating requests that
# belong to the same conversation is also the only way to close report.md 8.1 (a secret
# forgotten once its source scrolls out of the kit's 12-item conversation window): the
# contract gives no other handle for "these requests are the same run".
RUN_SCOPED_MEMORY = {"recall.py"}
LABEL_FIELDS = {"run_id", "step_id"}

# The shapes the organizers' invented names take: addresses, record ids (INV-4471,
# CASE-7001), synthetic domains, and snake_case scenario and family names. Ordinary
# English prose produces none of these.
CORPUS_IDENTIFIER = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    r"|\b[A-Za-z]{2,}-[A-Za-z0-9]{2,}(?:-[A-Za-z0-9]+)*\b"
    r"|\b[a-z0-9-]+\.(?:example|test|invalid|local)\b"
    r"|\b[a-z]+_[a-z]+(?:_[a-z]+)+\b"
)

# Names the contract itself defines. We are required to read these, so their presence in
# both the kit and our source is the interface working, not scenario data leaking in.
CONTRACT_VOCABULARY = frozenset(
    {
        "allowed_tools",
        "consequential_tools",
        "confirmation_required_tools",
        "internal_email_domains",
        "policy_id",
        "policy_version",
        "confirmations_granted",
        "least_trusted_seen",
        "most_sensitive_seen",
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
        "requires_confirmation",
        "forbidden_effect",
        "tool_permission",
        "data_flow",
        "prerequisite",
        "request_confirmation",
        "memory_write",
        "tool_call",
        "rewritten_action",
        "risk_score",
        "reason_codes",
        "candidate_action",
        "history_digest",
        "provenance_ids",
        "trust_level",
        "source_type",
        "source_id",
        "origin_actor",
        "retrieved_via",
        "steps_taken",
        "turn_index",
        "tool_calls",
        "blocked_count",
        "escalated_count",
        "user_goal",
        "step_id",
        "run_id",
    }
)


def _kit_root() -> pathlib.Path | None:
    for candidate in (
        os.environ.get("SENTINEL_KIT"),
        pathlib.Path.home() / "Desktop" / "Sentinel_Starter_Kit",
        # docs/KIT_PATH.md tells a reader to clone the kit; most clone it straight into the
        # checkout they are already sitting in. That used to be invisible to this list, so
        # the audit skipped by default and only CI -- which sets SENTINEL_KIT -- was covered.
        SOURCE.parents[1] / "Sentinel_Starter_Kit",
        SOURCE.parents[2] / "Sentinel_Starter_Kit",
    ):
        if candidate is None:
            continue
        path = pathlib.Path(candidate)
        if (path / "scenarios").is_dir():
            return path
    return None


def _defense_modules() -> list[pathlib.Path]:
    return sorted(p for p in SOURCE.glob("*.py") if p.name != "__init__.py")


def _corpus_identifiers(kit: pathlib.Path) -> set[str]:
    found: set[str] = set()
    for folder in ("scenarios", "fixtures", "policies"):
        root = kit / folder
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".yaml", ".yml", ".json"}:
                continue
            # A JSON Schema describes structure, not scenario data, and its `pattern`
            # fields are regexes whose character classes ("za-z0-9") read as identifiers.
            if "schema" in path.name.lower():
                continue
            found.add(path.stem.lower())
            text = path.read_text(encoding="utf-8", errors="ignore")
            found.update(match.group(0).lower() for match in CORPUS_IDENTIFIER.finditer(text))
    return {
        i
        for i in found
        if len(i) >= MIN_LITERAL_CHARS
        # A contract name and its singular or plural form are both the interface.
        and not any(i in term or term in i for term in CONTRACT_VOCABULARY)
    }


def test_the_extractor_matches_the_shapes_it_claims_to() -> None:
    """Guards the audit against going vacuously green."""
    for sample in (
        "INV-4471",
        "CASE-7001",
        "billing@lumen-supplies.example",
        "lumen-supplies.example",
        "indirect_prompt_injection",
    ):
        assert CORPUS_IDENTIFIER.search(sample), f"extractor no longer matches {sample!r}"
    assert not CORPUS_IDENTIFIER.search("ordinary english prose without identifiers")


def test_the_corpus_yields_identifiers_to_search_for() -> None:
    kit = _kit_root()
    if kit is None:
        pytest.skip("starter kit not available; set SENTINEL_KIT to enable the corpus check")
    assert len(_corpus_identifiers(kit)) > 100, "corpus extraction collapsed; the audit is vacuous"


def test_no_organizer_identifier_appears_in_the_defense() -> None:
    kit = _kit_root()
    if kit is None:
        pytest.skip("starter kit not available; set SENTINEL_KIT to enable the corpus check")

    source = "\n".join(module.read_text(encoding="utf-8").lower() for module in _defense_modules())
    offenders = sorted(i for i in _corpus_identifiers(kit) if i in source)
    assert not offenders, (
        "identifiers invented by the organizers appear in the defense source, which is "
        f"the disqualification rule: {offenders[:20]}"
    )


def test_the_decision_path_never_reads_a_scenario_label() -> None:
    offenders: list[str] = []
    for module in _defense_modules():
        if module.name in OBSERVABILITY_ONLY or module.name in RUN_SCOPED_MEMORY:
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in LABEL_FIELDS:
                offenders.append(f"{module.name}:{node.lineno} reads {node.attr}")
    assert not offenders, f"a scenario label reaches the decision path: {offenders}"


def test_every_defense_module_is_covered_by_this_audit() -> None:
    """A new module must not slip past the audit by being added after it was written."""
    assert len(_defense_modules()) >= 14, "defense modules moved; re-check the audit scope"


def test_kit_root_finds_a_kit_placed_inside_the_checkout(tmp_path, monkeypatch) -> None:
    """`docs/KIT_PATH.md` tells a reader to clone the kit; most clone it into the checkout,
    where the disqualification audit above silently skipped it until this candidate existed
    -- CI stayed green only because it sets SENTINEL_KIT explicitly. A tmp_path stand-in
    proves the candidate without depending on a real clone sitting on disk.
    """
    monkeypatch.delenv("SENTINEL_KIT", raising=False)
    # Neutralize the Desktop candidate so this test cannot pass or fail on what happens to
    # be sitting on the machine that runs it.
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path / "not-a-real-home")
    checkout = tmp_path / "checkout"
    kit = checkout / "Sentinel_Starter_Kit"
    (kit / "scenarios").mkdir(parents=True)
    monkeypatch.setattr(sys.modules[__name__], "SOURCE", checkout / "src" / "haris")
    assert _kit_root() == kit
