"""Serves the HARIS trace viewer.

One FastAPI process, one static page, no build step. It reads run artifacts from disk
and the HARIS journal beside them, so it works against any completed run without the
defense being live.

Runs live in more than one place: the kit's evals write under the kit's `artifacts/`,
our red-team harness under this repository's. `HARIS_ARTIFACTS` and `HARIS_JOURNAL_PATH`
therefore take an os.pathsep-separated list, the same shape as PATH.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from dashboard.trace import discover_runs, load_run
from haris.config import SETTINGS

STATIC = Path(__file__).parent / "static"


def _path_list(value: str) -> list[Path]:
    return [Path(part) for part in value.split(os.pathsep) if part.strip()]


def artifact_roots() -> list[Path]:
    return _path_list(os.environ.get("HARIS_ARTIFACTS", "artifacts"))


def journal_paths(roots: Sequence[Path]) -> list[Path]:
    """An explicit journal wins; otherwise each root's own `haris/journal.jsonl`."""
    explicit = _path_list(os.environ.get("HARIS_JOURNAL_PATH", ""))
    return explicit or [root / "haris" / "journal.jsonl" for root in roots]


def _as_list(value: Path | Sequence[Path] | None) -> list[Path]:
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [Path(value)]
    return [Path(v) for v in value]


def create_app(artifacts: Path | Sequence[Path] | None = None, journal: Path | Sequence[Path] | None = None) -> FastAPI:
    roots = [root.resolve() for root in (_as_list(artifacts) or artifact_roots())]
    journals = _as_list(journal) or journal_paths(roots)

    app = FastAPI(title="HARIS trace viewer")

    # One scan at a time, shared by every poll that arrives while it runs. Behind Docker
    # Desktop a scan of a large artifacts folder took minutes; the page polls every five
    # seconds, so each poll started another scan and they piled up. A scan that finished
    # after a request arrived is as fresh as a new one, so waiting requests reuse it and a
    # later request still rescans: new runs keep appearing.
    listing_lock = threading.Lock()
    listing: dict[str, Any] = {"finished": float("-inf"), "runs": []}

    def _listed_runs() -> list[dict[str, Any]]:
        asked = time.perf_counter()
        with listing_lock:
            if listing["finished"] > asked:
                return listing["runs"]
            found = discover_runs(roots)
            listing.update(finished=time.perf_counter(), runs=found)
            return found

    # The first listing reads every trace once; behind Docker Desktop's file sharing that
    # took two minutes for ~3,500 runs, and later listings take under a second. The
    # container asks for it at startup, in the background, so the page is usually ready by
    # the time anyone opens it. Off by default: tests and local runs list on demand.
    if os.environ.get("HARIS_DASHBOARD_PRELOAD") == "1":
        threading.Thread(target=_listed_runs, name="preload-runs", daemon=True).start()

    def _checked(path: str) -> Path:
        """Reject anything outside the artifacts roots: this endpoint reads by path."""
        candidate = Path(path).resolve()
        if not any(candidate.is_relative_to(root) for root in roots):
            raise HTTPException(status_code=400, detail="path is outside the artifacts directory")
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="no run artifact at that path")
        return candidate

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config")
    def config() -> JSONResponse:
        # Read at request time from the engine's own settings, so the thresholds drawn on
        # the score bar can never drift from the ones that produced the decision.
        return JSONResponse(
            {
                "thresholds": {"escalate": SETTINGS.escalate_threshold, "block": SETTINGS.block_threshold},
                "roots": [str(root) for root in roots],
                "journals": [str(path) for path in journals],
            }
        )

    @app.get("/api/runs")
    def runs() -> JSONResponse:
        listed = [str(root) for root in roots]
        if not any(root.is_dir() for root in roots):
            return JSONResponse(
                {"runs": [], "root": listed[0] if listed else "", "roots": listed, "error": "artifacts directory not found"}
            )
        return JSONResponse({"runs": _listed_runs(), "root": listed[0], "roots": listed})

    @app.get("/api/run")
    def run(path: str = Query(...)) -> JSONResponse:
        return JSONResponse(load_run(_checked(path), journals))

    return app


app = create_app()
