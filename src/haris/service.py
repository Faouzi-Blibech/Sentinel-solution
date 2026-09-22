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

# /v1/guard speaks haris.guard.Verdict, not DefenseDecision -- different field names
# (risk, not risk_score; rewritten, not rewritten_action) -- so it needs its own fallback
# shape. Restated here rather than imported from haris.guard for the same reason
# defense.py restates service.py's _SAFE_FALLBACK: this dict must stay constructible
# even when haris.guard itself fails to import.
_GUARD_SAFE_FALLBACK: dict[str, Any] = {
    "decision": "escalate",
    "risk": 0.5,
    "confidence": 0.0,
    "reason_codes": ["HARIS_INTERNAL_ERROR"],
    "explanation": "HARIS could not evaluate this action; deferring to a human.",
    "rewritten": None,
    "metadata": {},
}

# What the defense cannot run without: the contract types the simulator speaks, and our
# own decision path. Importing them is the cheapest honest proof the process is usable.
CONTRACT = "sentinel-bench (sentinel.core, sentinel.defenses)"


def _probe() -> None:
    import sentinel.core.actions  # noqa: F401
    import sentinel.defenses.interface  # noqa: F401

    from haris.engine import decide_from_payload  # noqa: F401

    # /v1/guard is a second front door onto the same decision core, with its own import
    # (sentinel.core.provenance, transitively) and its own degrade-to-escalate fallback.
    # Without this line a bug isolated to haris.guard would report /healthz "ok" while
    # that one surface silently escalated everything -- the exact monitoring failure
    # this probe exists to catch, just scoped to the surface /v1/decision doesn't cover.
    from haris.guard import HarisGuard  # noqa: F401


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


@app.post("/v1/guard")
def guard(payload: dict[str, Any]) -> JSONResponse:
    """The HTTP twin of `haris.guard.HarisGuard`, for a caller not in Python.

    A sibling of `/v1/decision`, not a replacement: that endpoint's contract (request
    shape, response shape, `/healthz`) is unchanged. This one speaks OpenAI/Anthropic-
    shaped tool calls instead of `DefenseRequest`, and returns `Verdict`-shaped JSON
    (`risk`, `rewritten`) instead of `DefenseDecision`-shaped JSON (`risk_score`,
    `rewritten_action`) -- deliberately not the same field names, so a caller can never
    mix the two responses up by accident.

    Imported inside the handler, exactly like `/v1/decision` imports `decide_from_payload`
    inside its own: a missing contract package must degrade this endpoint, not take down
    module import of the whole service (service.py's own docstring explains why that
    matters -- a service that fails to import looks nothing like "healthy", while one
    that imports fine and escalates everything can look healthy by mistake).
    """
    try:
        from haris.guard import HarisGuard

        body = payload if isinstance(payload, dict) else {}
        policy = body.get("policy") if isinstance(body.get("policy"), dict) else {}

        instance = HarisGuard(
            allowed_tools=policy.get("allowed_tools"),
            consequential_tools=policy.get("consequential_tools"),
            confirmation_required_tools=policy.get("confirmation_required_tools"),
            internal_email_domains=policy.get("internal_email_domains"),
            rules=policy.get("rules"),
            policy_id=policy.get("policy_id", "haris.guard"),
        )

        proposed = body.get("proposed")
        if proposed is None:
            proposed = body.get("proposed_tool_call")

        verdict = instance.check(
            goal=str(body.get("goal", "")),
            proposed=proposed,
            messages=body.get("messages") or (),
            sources=body.get("sources") or (),
            run_id=body.get("run_id"),
            step_id=body.get("step_id"),
            confirmations=body.get("confirmations") or (),
        )
        return JSONResponse(
            {
                "decision": verdict.decision,
                "risk": verdict.risk,
                "confidence": verdict.confidence,
                "reason_codes": verdict.reason_codes,
                "explanation": verdict.explanation,
                "rewritten": verdict.rewritten,
                "metadata": verdict.metadata,
            }
        )
    except Exception:  # noqa: BLE001 -- same CLOSED-fail-mode posture as /v1/decision
        return JSONResponse(_GUARD_SAFE_FALLBACK)
