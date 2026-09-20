"""Serves the HARIS trace viewer.

One FastAPI process, one static page, no build step. It reads run artifacts from disk
and the HARIS journal beside them, so it works against any completed run without the
defense being live.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from dashboard.trace import discover_runs, load_run

STATIC = Path(__file__).parent / "static"
DEFAULT_ARTIFACTS = Path(os.environ.get("HARIS_ARTIFACTS", "artifacts"))
DEFAULT_JOURNAL = Path(os.environ.get("HARIS_JOURNAL_PATH", Path("artifacts") / "haris" / "journal.jsonl"))


def create_app(artifacts: Path | None = None, journal: Path | None = None) -> FastAPI:
    root = Path(artifacts or DEFAULT_ARTIFACTS).resolve()
    journal_path = Path(journal or DEFAULT_JOURNAL)

    app = FastAPI(title="HARIS trace viewer")

    def _checked(path: str) -> Path:
        """Reject anything outside the artifacts root: this endpoint reads by path."""
        candidate = Path(path).resolve()
        if not candidate.is_relative_to(root):
            raise HTTPException(status_code=400, detail="path is outside the artifacts directory")
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="no run artifact at that path")
        return candidate

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/runs")
    def runs() -> JSONResponse:
        if not root.is_dir():
            return JSONResponse({"runs": [], "root": str(root), "error": "artifacts directory not found"})
        return JSONResponse({"runs": discover_runs(root), "root": str(root)})

    @app.get("/api/run")
    def run(path: str = Query(...)) -> JSONResponse:
        return JSONResponse(load_run(_checked(path), journal_path))

    return app


app = create_app()
