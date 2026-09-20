"""Joins the simulator's trace to the HARIS journal.

The trace says what happened: events, tool calls, results, the graded outcome. It does
not say why, because DecisionRecord drops the decision metadata and no trust level ever
reaches the artifact. The journal supplies the reasoning. They join on (run_id, step_id).

Everything here degrades gracefully: a trace recorded by any other defense still renders,
just without the signal decomposition.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

DECISIONS = ("allow", "block", "escalate", "rewrite")


def parse_trace(lines: Iterable[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    events.sort(key=lambda e: e.get("seq", 0))
    return events


def parse_journal(lines: Iterable[str]) -> dict[tuple[str, int], dict[str, Any]]:
    index: dict[tuple[str, int], dict[str, Any]] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = (entry.get("run_id", ""), int(entry.get("step_id", -1)))
        # A rerun appends; the last write for a step is the current one.
        index[key] = entry
    return index


def _goal(events: list[dict[str, Any]]) -> str:
    for event in events:
        if event.get("type") == "user_message":
            return str(event.get("payload", {}).get("text", ""))
    return ""


def _outcome(events: list[dict[str, Any]]) -> dict[str, Any]:
    outcome: dict[str, Any] = {"task_success": None, "conditions": None}
    for event in events:
        kind = event.get("type")
        if kind == "task_success":
            outcome["task_success"] = True
            outcome["conditions"] = event.get("payload", {})
        elif kind == "task_failure":
            outcome["task_success"] = False
            outcome["conditions"] = event.get("payload", {})
        elif kind == "policy_violation":
            outcome.setdefault("violations", []).append(event.get("payload", {}))
    return outcome


def build_view(events: list[dict[str, Any]], journal: dict[tuple[str, int], dict[str, Any]]) -> dict[str, Any]:
    run_id = events[0].get("run_id", "") if events else ""
    by_step: dict[int, dict[str, Any]] = {}

    for event in events:
        step_id = int(event.get("step_id", 0))
        step = by_step.setdefault(
            step_id,
            {"step_id": step_id, "events": [], "decision": None, "signals": [], "dataflow": {}, "journal": None},
        )
        step["events"].append(event)
        if event.get("type") == "defense_decision":
            step["decision"] = event.get("payload", {})

    provenance: dict[str, Any] = {}
    counts = dict.fromkeys(DECISIONS, 0)

    for step_id, step in by_step.items():
        entry = journal.get((run_id, step_id))
        if entry is not None:
            step["journal"] = entry
            metadata = entry.get("metadata") or {}
            step["signals"] = list(metadata.get("signals") or [])
            step["dataflow"] = dict(metadata.get("dataflow") or {})
            step["trust"] = dict(metadata.get("trust") or {})
            step["timings"] = dict(metadata.get("stage_timings_ms") or {})
            for record in entry.get("provenance") or []:
                provenance[record["id"]] = record
        decision = step.get("decision") or {}
        name = decision.get("decision")
        if name in counts:
            counts[name] += 1

    steps = [by_step[key] for key in sorted(by_step)]
    return {
        "run_id": run_id,
        "scenario": run_id.split("-")[0] if run_id else "",
        "goal": _goal(events),
        "outcome": _outcome(events),
        "steps": steps,
        "provenance": provenance,
        "counts": counts,
        "has_reasoning": any(step["signals"] for step in steps),
    }


def _scenario_of(path: Path) -> str:
    """Artifacts are named <scenario>-<defense>-s<seed>.jsonl."""
    stem = path.stem
    for marker in ("-http_defense", "-allow_all", "-keyword", "-heuristic_risk", "-provenance", "-deny_sensitive"):
        if marker in stem:
            return stem.split(marker)[0]
    return stem.rsplit("-", 2)[0] if stem.count("-") >= 2 else stem


def load_run(trace_path: Path, journal_path: Path | None = None) -> dict[str, Any]:
    events = parse_trace(trace_path.read_text(encoding="utf-8").splitlines())
    journal: dict[tuple[str, int], dict[str, Any]] = {}
    if journal_path is not None and journal_path.is_file():
        journal = parse_journal(journal_path.read_text(encoding="utf-8").splitlines())
    view = build_view(events, journal)
    view["scenario"] = _scenario_of(trace_path)
    view["source"] = str(trace_path)
    return view


def discover_runs(root: Path, latest_only: bool = True) -> list[dict[str, Any]]:
    """Run artifacts under a directory, newest first.

    Each eval writes its own timestamped directory, so a week of debugging leaves
    scores of near-identical runs. By default only the newest run per scenario is
    returned: that is the one produced by the current build.
    """
    runs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(Path(root).rglob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.name == "journal.jsonl":
            continue
        try:
            events = parse_trace(path.read_text(encoding="utf-8").splitlines())
        except OSError:
            continue
        if not events:
            continue
        scenario = _scenario_of(path)
        if latest_only:
            if scenario in seen:
                continue
            seen.add(scenario)
        runs.append(
            {
                "id": str(path),
                "scenario": scenario,
                "run_id": events[0].get("run_id", ""),
                "steps": len({e.get("step_id", 0) for e in events}),
                "outcome": _outcome(events),
                "modified": path.stat().st_mtime,
            }
        )
    return runs
