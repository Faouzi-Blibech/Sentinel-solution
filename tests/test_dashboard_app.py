import json

import pytest
from fastapi.testclient import TestClient

from dashboard.app import create_app
from tests.test_trace import TRACE

pytestmark = pytest.mark.usefixtures()


@pytest.fixture()
def client(tmp_path):
    run_dir = tmp_path / "artifacts" / "eval-public-http_defense-1"
    run_dir.mkdir(parents=True)
    (run_dir / "enterprise_poisoned_invoice-http_defense-s0.jsonl").write_text(
        "\n".join(json.dumps(e) for e in TRACE), encoding="utf-8"
    )
    (tmp_path / "secret.jsonl").write_text("{}", encoding="utf-8")
    return TestClient(create_app(tmp_path / "artifacts")), tmp_path


def test_index_serves_the_page(client):
    api, _ = client
    response = api.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_runs_endpoint_lists_discovered_runs(client):
    api, _ = client
    body = api.get("/api/runs").json()
    assert len(body["runs"]) == 1
    assert body["runs"][0]["scenario"] == "enterprise_poisoned_invoice"


def test_run_endpoint_returns_the_joined_view(client):
    api, _ = client
    path = api.get("/api/runs").json()["runs"][0]["id"]
    body = api.get("/api/run", params={"path": path}).json()
    assert body["goal"].startswith("Summarize the dispute")
    assert body["counts"]["block"] == 1


def test_run_endpoint_refuses_paths_outside_the_artifacts_root(client):
    api, tmp_path = client
    response = api.get("/api/run", params={"path": str(tmp_path / "secret.jsonl")})
    assert response.status_code == 400


def test_run_endpoint_reports_a_missing_file_clearly(client):
    api, tmp_path = client
    missing = tmp_path / "artifacts" / "nope.jsonl"
    response = api.get("/api/run", params={"path": str(missing)})
    assert response.status_code == 404
