"""HTTP surface for the defense.

The simulator's fail mode defaults to CLOSED: an exception here makes it block
every action, which collapses benign utility below the eligibility gate. So this
module never raises, whatever happens downstream.

That guarantee has a dark side, and it bit us. When the contract package is missing the
import inside the endpoint fails, the handler returns its safe fallback, and the service
escalates *every* action while `/healthz` returns 200. A defense that silently degrades
to "ask a human about everything" and reports itself healthy is the monitoring failure
this whole project is about. So readiness is a live probe: it tries to reach a decision
and says what went wrong when it cannot.
"""

from __future__ import annotations

from collections.abc import Callable
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

# What the defense cannot run without: the contract types the simulator speaks, and our
# own decision path. Importing them is the cheapest honest proof the process is usable.
CONTRACT = "sentinel-bench (sentinel.core, sentinel.defenses)"


def _probe() -> None:
    import sentinel.core.actions  # noqa: F401
    import sentinel.defenses.interface  # noqa: F401

    from haris.engine import decide_from_payload  # noqa: F401


_PROBE: Callable[[], None] = _probe


def readiness(probe: Callable[[], None] | None = None) -> tuple[bool, str]:
    """Can this process actually reach a decision right now?"""
    try:
        (probe or _PROBE)()
    except Exception as error:  # noqa: BLE001 -- the reason is the point of the probe
        return False, f"{type(error).__name__}: {error}"
    return True, "decision path importable"


@app.get("/healthz")
def healthz() -> JSONResponse:
    ready, detail = readiness()
    return JSONResponse(
        {"status": "ok" if ready else "degraded", "ready": ready, "contract": CONTRACT, "detail": detail},
        status_code=200 if ready else 503,
    )


@app.post("/v1/decision")
def decision(payload: dict[str, Any]) -> JSONResponse:
    try:
        from haris.engine import decide_from_payload

        return JSONResponse(decide_from_payload(payload))
    except Exception:  # noqa: BLE001 -- CLOSED fail mode means a raise blocks everything
        return JSONResponse(_SAFE_FALLBACK)
