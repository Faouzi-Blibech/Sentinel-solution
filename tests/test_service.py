from fastapi.testclient import TestClient

from haris.service import app

client = TestClient(app)


def test_healthz_returns_200():
    assert client.get("/healthz").status_code == 200


def test_decision_never_raises_on_garbage():
    """fail_mode is CLOSED upstream, so a 500 would block every action."""
    response = client.post("/v1/decision", json={"nonsense": True})
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] in {"allow", "block", "escalate", "rewrite"}
    assert 0.0 <= body["risk_score"] <= 1.0
