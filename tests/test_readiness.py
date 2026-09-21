"""A health check that lies is worse than no health check.

The service catches every exception and returns ESCALATE, because the simulator fails
closed and a raise would block every action. That guarantee has a dark side: when the
contract package is missing, the import inside the endpoint fails, and the service
escalates *everything* while `/healthz` cheerfully returns 200. A judge running the
container sees a defense that works and blocks nothing.

That is exactly what was happening. `sentinel` is imported by ten modules in
`src/haris/` and was declared in no dependency list, so `pip install .` in the Dockerfile
produced an image whose every decision was HARIS_INTERNAL_ERROR.

So readiness is now a real question -- can this process actually reach a decision? --
and the answer is computed rather than asserted.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from haris.service import app

client = TestClient(app)


def test_healthz_reports_ready_when_the_defense_can_decide() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["ready"] is True


def test_healthz_names_the_contract_it_depends_on() -> None:
    """A judge reading the health output should see what is missing, not just 'ok'."""
    body = client.get("/healthz").json()
    assert "contract" in body


def test_readiness_probe_is_computed_not_hardcoded() -> None:
    """Guards against the check becoming a constant again."""
    from haris import service

    ready, detail = service.readiness()
    assert ready is True
    assert isinstance(detail, str) and detail

    broken = service.readiness(probe=lambda: (_ for _ in ()).throw(ImportError("no sentinel")))
    assert broken[0] is False
    assert "no sentinel" in broken[1]


def test_a_service_that_cannot_decide_fails_its_health_check() -> None:
    from haris import service

    original = service._PROBE
    try:
        service._PROBE = lambda: (_ for _ in ()).throw(ImportError("contract missing"))
        response = client.get("/healthz")
        assert response.status_code == 503
        assert response.json()["ready"] is False
    finally:
        service._PROBE = original

    # And it recovers once the cause is gone, so the probe is genuinely live.
    assert client.get("/healthz").status_code == 200
