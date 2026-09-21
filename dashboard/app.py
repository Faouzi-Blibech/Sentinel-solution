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
from collections.abc import Sequence
from pathlib import Path

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
        return JSONResponse({"runs": discover_runs(roots), "root": listed[0], "roots": listed})

    @app.get("/api/run")
    def run(path: str = Query(...)) -> JSONResponse:
        return JSONResponse(load_run(_checked(path), journals))

    return app


app = create_app()
