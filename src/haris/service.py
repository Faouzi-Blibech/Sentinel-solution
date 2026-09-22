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
    "action_digest": None,
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


def _guard_probe() -> None:
    from haris.guard import HarisGuard  # noqa: F401


_GUARD_PROBE: Callable[[], None] = _guard_probe


def guard_readiness(probe: Callable[[], None] | None = None) -> tuple[bool, str]:
    """Whether POST /v1/guard can be reached, checked and reported SEPARATELY from
    `readiness()`.

    This used to be folded into `_PROBE` itself, on the reasoning that a bug isolated to
    `haris.guard` should not report `/healthz` healthy while that one surface silently
    escalated everything. A review round reverted it: the kit's own submission check
    (`sandbox/submission.py`'s `live_healthz`) fails on anything but a 200 from
    `/healthz`, so coupling the two would let an adapter-only bug fail the ORGANIZERS'
    submission gate while `/v1/decision` -- the thing actually scored -- still works
    perfectly. Reporting guard readiness as its own field, never touching the top-level
    `status`/`ready`/status code, gets the same observability without that risk.
    """
    try:
        (probe or _GUARD_PROBE)()
    except Exception as error:  # noqa: BLE001 -- the reason is the point of the probe
        return False, f"{type(error).__name__}: {error}"
    return True, "guard path importable"


@app.get("/healthz")
def healthz() -> JSONResponse:
    ready, detail = readiness()
    guard_ready, guard_detail = guard_readiness()
    return JSONResponse(
        {
            "status": "ok" if ready else "degraded",
            "ready": ready,
            "contract": CONTRACT,
            "detail": detail,
            # Informational only: never affects `status`/`ready`/the status code above.
            "guard": {"ready": guard_ready, "detail": guard_detail},
        },
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

    A fresh `HarisGuard` is built per request, so `run_id` matters here more than it
    does in-process: without one, every un-labelled call gets its OWN random taint
    bucket (`HarisGuard.__init__`), so nothing is ever shared between two different
    HTTP clients -- but nothing is remembered between two calls of the SAME
    conversation either, unless the caller passes the same `run_id` on both. A
    multi-turn agent calling this endpoint should generate one `run_id` per
    conversation and send it on every call.
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

        # A caller may reasonably send an id-shaped value (an int, a UUID object from a
        # loosely-typed client) rather than a string; stringifying it here is a faithful
        # representation (an id is metadata, never content the taint scan reads), unlike
        # truncating an argument or a final answer would be.
        run_id = body.get("run_id")
        if run_id is not None and not isinstance(run_id, str):
            run_id = str(run_id)

        verdict = instance.check(
            goal=str(body.get("goal", "")),
            proposed=proposed,
            messages=body.get("messages") or (),
            sources=body.get("sources") or (),
            run_id=run_id,
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
                "action_digest": verdict.action_digest,
            }
        )
    except Exception:  # noqa: BLE001 -- same CLOSED-fail-mode posture as /v1/decision
        return JSONResponse(_GUARD_SAFE_FALLBACK)
