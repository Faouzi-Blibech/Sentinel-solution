"""HTTP surface for the defense.

The simulator's fail mode defaults to CLOSED: an exception here makes it block
every action, which collapses benign utility below the eligibility gate. So this
module never raises, whatever happens downstream.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="HARIS", version="1.0.0")

_SAFE_FALLBACK: dict[str, Any] = {
    "decision": "escalate",
    "risk_score": 0.5,
    "confidence": 0.0,
    "reason_codes": ["HARIS_INTERNAL_ERROR"],
    "explanation": "HARIS could not evaluate this action; deferring to a human.",
    "rewritten_action": None,
    "metadata": {},
}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision")
def decision(payload: dict[str, Any]) -> JSONResponse:
    try:
        from haris.engine import decide_from_payload

        return JSONResponse(decide_from_payload(payload))
    except Exception:  # noqa: BLE001 -- CLOSED fail mode means a raise blocks everything
        return JSONResponse(_SAFE_FALLBACK)
