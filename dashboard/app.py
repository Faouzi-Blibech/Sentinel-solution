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

    @app.get("/guard")
    def guard_console() -> FileResponse:
        """The connect-your-agent console.

        The trace viewer can only show runs the simulator produced, and the guard is called
        by agents the simulator never runs -- so guard decisions have no artifact to appear
        in. This page is where that half of HARIS is visible: it calls the guard in-process,
        which means no second server, no CORS, and no change to the scored service.
        """
        return FileResponse(STATIC / "guard.html")

    @app.post("/api/guard")
    def guard_check(payload: dict) -> JSONResponse:
        # In-process on purpose. Proxying to the live service would make this page depend on
        # a second process being up and on a cross-origin request the browser would block.
        try:
            from haris.guard import HarisGuard

            body = payload if isinstance(payload, dict) else {}
            policy = body.get("policy") if isinstance(body.get("policy"), dict) else {}
            guard = HarisGuard(
                allowed_tools=policy.get("allowed_tools"),
                consequential_tools=policy.get("consequential_tools"),
                confirmation_required_tools=policy.get("confirmation_required_tools"),
                internal_email_domains=policy.get("internal_email_domains"),
            )
            verdict = guard.check(
                goal=str(body.get("goal", "")),
                proposed=body.get("proposed"),
                messages=body.get("messages") or (),
                sources=body.get("sources") or (),
                run_id=body.get("run_id"),
            )
            return JSONResponse(
                {
                    "decision": verdict.decision,
                    "risk": verdict.risk,
                    "confidence": verdict.confidence,
                    "reason_codes": verdict.reason_codes,
                    "explanation": verdict.explanation,
                    "rewritten": verdict.rewritten,
                    "action_digest": verdict.action_digest,
                    "metadata": verdict.metadata,
                }
            )
        except Exception as error:  # noqa: BLE001 -- a console must report, never 500
            return JSONResponse({"error": f"{type(error).__name__}: {error}"}, status_code=200)

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
