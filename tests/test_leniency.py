"""The simulator may send fields our pinned schema does not know about.

DefenseRequest is extra="forbid", so an unknown field would make every decision fall
through to the internal-error fallback. With fail_mode CLOSED upstream that collapses
benign utility below the eligibility gate, which is the worst outcome available.
"""

from fastapi.testclient import TestClient

from haris.service import app
from tests.factories import make_request

client = TestClient(app)


def _payload(**extra):
    body = make_request(
        user_goal="Read the newsletter and summarize it.",
        policy_context={"allowed_tools": ["document_read"]},
    ).model_dump(mode="json")
    body.update(extra)
    return body


def test_unknown_top_level_field_still_gets_a_real_decision():
    response = client.post("/v1/decision", json=_payload(benchmark_version="9.9", future_field=[1, 2]))
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert "HARIS_INTERNAL_ERROR" not in body["reason_codes"]


def test_unknown_nested_field_still_gets_a_real_decision():
    payload = _payload()
    payload["history_digest"]["unknown_counter"] = 3
    payload["candidate_action"]["future_flag"] = True
    response = client.post("/v1/decision", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert "HARIS_INTERNAL_ERROR" not in body["reason_codes"]


def test_genuinely_malformed_request_still_returns_a_valid_decision():
    response = client.post("/v1/decision", json={"run_id": "r"})
    assert response.status_code == 200
    assert response.json()["decision"] in {"allow", "block", "escalate", "rewrite"}
