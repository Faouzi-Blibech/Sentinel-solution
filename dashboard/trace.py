"""Joins the simulator's trace to the HARIS journal.

The trace says what happened: events, tool calls, results, the graded outcome. It does
not say why, because DecisionRecord drops the decision metadata and no trust level ever
reaches the artifact. The journal supplies the reasoning. They join on (run_id, step_id).

The kit also writes `<run_id>.summary.json` beside every trace. It carries the
scenario's own labels -- domain, attack family, hard negative, whether the attack
succeeded -- so the viewer never has to guess them from a filename.

Everything here degrades gracefully: a trace recorded by any other defense still renders,
just without the signal decomposition.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

DECISIONS = ("allow", "block", "escalate", "rewrite")

# The kit's own defense names. A filename is only parsed when no summary sits beside it.
_DEFENSE_MARKERS = ("http_defense", "allow_all", "keyword", "heuristic_risk", "provenance", "deny_sensitive")

_SUMMARY_FIELDS = (
    "scenario_id",
    "defense",
    "domain",
    "split",
    "seed",
    "attack_present",
    "attack_family",
    "hard_negative",
    "difficulty",
    "task_success",
    "attack_success",
    "critical_violation",
    "data_flow_violation",
    "termination",
)

# Parsed runs and journals, keyed on file identity. The viewer polls /api/runs, and
# re-reading every trace on every poll grows with each eval left on disk.
_RUN_CACHE: dict[Path, tuple[tuple[int, ...], dict[str, Any]]] = {}
_JOURNAL_CACHE: dict[Path, tuple[tuple[int, ...], dict[tuple[str, int], dict[str, Any]]]] = {}
# Per folder: its mtime when listed, the run files in it with (mtime_ns, size), and its
# subfolders. See _scan: an old, unchanged folder is not listed again.
_FOLDER_CACHE: dict[str, tuple[int, dict[str, tuple[int, int]], list[str]]] = {}
# A folder changed this recently may hold a scenario still appending to its trace. A
# real-model scenario runs for a few minutes; fifteen is a wide margin.
LIVE_WINDOW_S = 15 * 60


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


def _counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(DECISIONS, 0)
    for event in events:
        if event.get("type") == "defense_decision":
            name = (event.get("payload") or {}).get("decision")
            if name in counts:
                counts[name] += 1
    return counts


def build_view(events: list[dict[str, Any]], journal: dict[tuple[str, int], dict[str, Any]]) -> dict[str, Any]:
    run_id = events[0].get("run_id", "") if events else ""
    by_step: dict[int, dict[str, Any]] = {}

    for event in events:
        step_id = int(event.get("step_id", 0))
        step = by_step.setdefault(
            step_id,
            {
                "step_id": step_id,
                "events": [],
                "decision": None,
                "signals": [],
                "dataflow": {},
                "trust": {},
                "timings": {},
                "plan": {},
                "total_ms": None,
                "observation": None,
                "latency_ms": None,
                "journal": None,
            },
        )
        step["events"].append(event)
        if event.get("type") == "defense_decision":
            step["decision"] = event.get("payload", {})

    provenance: dict[str, Any] = {}

    for step_id, step in by_step.items():
        entry = journal.get((run_id, step_id))
        if entry is None:
            continue
        step["journal"] = entry
        metadata = entry.get("metadata") or {}
        step["signals"] = list(metadata.get("signals") or [])
        step["dataflow"] = dict(metadata.get("dataflow") or {})
        step["trust"] = dict(metadata.get("trust") or {})
        step["timings"] = dict(metadata.get("stage_timings_ms") or {})
        step["plan"] = dict(metadata.get("plan") or {})
        step["total_ms"] = metadata.get("total_ms")
        step["observation"] = entry.get("observation")
        for record in entry.get("provenance") or []:
            provenance[record["id"]] = record

    steps = [by_step[key] for key in sorted(by_step)]
    return {
        "run_id": run_id,
        "scenario": run_id.split("-")[0] if run_id else "",
        "goal": _goal(events),
        "outcome": _outcome(events),
        "steps": steps,
        "provenance": provenance,
        "counts": _counts(events),
        "has_reasoning": any(step["signals"] for step in steps),
    }


def _summary_path(trace_path: Path) -> Path:
    return trace_path.with_name(f"{trace_path.stem}.summary.json")


def _read_summary(trace_path: Path) -> dict[str, Any] | None:
    path = _summary_path(trace_path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_summary(trace_path: Path) -> dict[str, Any] | None:
    """The scenario's own labels, without the per-decision rows the viewer reads elsewhere."""
    data = _read_summary(trace_path)
    if data is None:
        return None
    summary = {name: data.get(name) for name in _SUMMARY_FIELDS}
    summary["graders"] = [
        {"condition": g.get("condition", ""), "detail": g.get("detail", ""), "passed": bool(g.get("passed"))}
        for g in data.get("grader_results") or []
        if isinstance(g, dict)
    ]
    return summary


def _latencies(trace_path: Path) -> dict[int, float]:
    """Round-trip latency the simulator measured for each decision, as the score sees it."""
    data = _read_summary(trace_path) or {}
    out: dict[int, float] = {}
    for record in data.get("decisions") or []:
        if isinstance(record, dict) and "step_id" in record and record.get("latency_ms") is not None:
            out[int(record["step_id"])] = float(record["latency_ms"])
    return out


def _scenario_of(path: Path) -> str:
    """Artifacts are named <scenario>-<defense>-s<seed>.jsonl."""
    stem = path.stem
    for marker in _DEFENSE_MARKERS:
        if f"-{marker}" in stem:
            return stem.split(f"-{marker}")[0]
    return stem.rsplit("-", 2)[0] if stem.count("-") >= 2 else stem


def _defense_of(path: Path) -> str:
    stem = path.stem
    for marker in _DEFENSE_MARKERS:
        if f"-{marker}" in stem:
            return marker
    return stem.rsplit("-", 2)[1] if stem.count("-") >= 2 else ""


def _labels(path: Path, summary: dict[str, Any] | None) -> tuple[str, str]:
    summary = summary or {}
    return (summary.get("scenario_id") or _scenario_of(path), summary.get("defense") or _defense_of(path))


def _as_paths(value: Path | str | Sequence[Path | str] | None) -> list[Path]:
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [Path(value)]
    return [Path(v) for v in value]


def _identity(*paths: Path) -> tuple[int, ...]:
    """File identity for the caches: a rewrite changes size or mtime, a new summary appears."""
    out: list[int] = []
    for path in paths:
        try:
            stat = path.stat()
            out += [stat.st_mtime_ns, stat.st_size]
        except OSError:
            out += [-1, -1]
    return tuple(out)


def _journal_index(path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    if not path.is_file():
        return {}
    identity = _identity(path)
    cached = _JOURNAL_CACHE.get(path)
    if cached is not None and cached[0] == identity:
        return cached[1]
    try:
        index = parse_journal(path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return {}
    _JOURNAL_CACHE[path] = (identity, index)
    return index


def load_run(trace_path: Path, journal_path: Path | Sequence[Path] | None = None) -> dict[str, Any]:
    events = parse_trace(trace_path.read_text(encoding="utf-8").splitlines())
    journal: dict[tuple[str, int], dict[str, Any]] = {}
    for path in _as_paths(journal_path):
        journal.update(_journal_index(path))
    view = build_view(events, journal)

    summary = load_summary(trace_path)
    view["scenario"], view["defense"] = _labels(trace_path, summary)
    view["summary"] = summary
    view["group"] = trace_path.parent.name
    view["source"] = str(trace_path)

    latencies = _latencies(trace_path)
    for step in view["steps"]:
        step["latency_ms"] = latencies.get(step["step_id"])
    return view


def _run_entry(
    path: Path, identity: tuple[int, ...] | None = None, modified: float | None = None
) -> dict[str, Any] | None:
    if identity is None:
        identity = _identity(path, _summary_path(path))
    cached = _RUN_CACHE.get(path)
    if cached is not None and cached[0] == identity:
        return cached[1]
    try:
        events = parse_trace(path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return None
    if not events:
        return None
    summary = load_summary(path)
    scenario, defense = _labels(path, summary)
    entry = {
        "id": str(path),
        "scenario": scenario,
        "defense": defense,
        "group": path.parent.name,
        "run_id": events[0].get("run_id", ""),
        "steps": len({e.get("step_id", 0) for e in events}),
        "outcome": _outcome(events),
        "counts": _counts(events),
        "summary": summary,
        "modified": modified if modified is not None else path.stat().st_mtime,
    }
    _RUN_CACHE[path] = (identity, entry)
    return entry


def _scan(base: Path) -> dict[str, tuple[int, int]]:
    """Every file under `base` with its (mtime_ns, size), from ONE directory walk.

    Behind Docker Desktop the artifacts are a Windows folder shared into the container,
    where each metadata call is slow: listing 3,500 traces took 238 s when every path was
    resolved (a lookup per path component) and then stat-ed again for the cache key. The
    walk already returns what both needed, so this is the only filesystem pass a warm
    listing makes.
    """
    found: dict[str, tuple[int, int]] = {}
    pending = [str(base)]
    live_since = time.time() - LIVE_WINDOW_S
    while pending:
        folder = pending.pop()
        try:
            folder_stat = os.stat(folder)
        except OSError:
            continue
        # Adding or removing a file changes its folder's time, so an unchanged folder
        # holds the same files. Appending to a file does NOT, and the kit appends to a
        # trace while its scenario runs: a folder changed within the live window is
        # always listed in full, so a run in progress keeps updating.
        cached = _FOLDER_CACHE.get(folder)
        if cached is not None and cached[0] == folder_stat.st_mtime_ns and folder_stat.st_mtime < live_since:
            found.update(cached[1])
            pending.extend(cached[2])
            continue
        files: dict[str, tuple[int, int]] = {}
        subfolders: list[str] = []
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    subfolders.append(entry.path)
                elif entry.name.endswith((".jsonl", ".summary.json")):
                    stat = entry.stat(follow_symlinks=False)
                    files[os.path.abspath(entry.path)] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                continue
        _FOLDER_CACHE[folder] = (folder_stat.st_mtime_ns, files, subfolders)
        found.update(files)
        pending.extend(subfolders)
    return found


def discover_runs(root: Path | Sequence[Path], latest_only: bool = True) -> list[dict[str, Any]]:
    """Run artifacts under one or more directories, newest first.

    Each eval writes its own timestamped directory, so a week of debugging leaves
    scores of near-identical runs. By default only the newest run per scenario and
    defense is returned: that is the one produced by the current build, and keeping
    one per defense is what lets a baseline sit beside HARIS on the same scenario.
    """
    stats: dict[str, tuple[int, int]] = {}
    for base in _as_paths(root):
        stats.update(_scan(base))
    missing = (-1, -1)
    files: dict[Path, int] = {
        Path(name): stat[0]
        for name, stat in stats.items()
        if name.endswith(".jsonl") and os.path.basename(name) != "journal.jsonl"
    }

    runs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(files, key=files.__getitem__, reverse=True):
        identity = stats[str(path)] + stats.get(str(_summary_path(path)), missing)
        entry = _run_entry(path, identity=identity, modified=files[path] / 1e9)
        if entry is None:
            continue
        if latest_only:
            key = (entry["scenario"], entry["defense"])
            if key in seen:
                continue
            seen.add(key)
        runs.append(entry)
    return runs
