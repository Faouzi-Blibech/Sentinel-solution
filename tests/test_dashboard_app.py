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


@pytest.fixture()
def two_roots(tmp_path):
    """The kit's evals and our red-team harness write to different directories."""
    kit = tmp_path / "kit" / "artifacts" / "eval-public-http_defense-1"
    repo = tmp_path / "repo" / "artifacts" / "redteam-heldout"
    for directory, stem in ((kit, "enterprise_poisoned_invoice-http_defense-s0"), (repo, "held_out_case-http_defense-s0")):
        directory.mkdir(parents=True)
        (directory / f"{stem}.jsonl").write_text("\n".join(json.dumps(e) for e in TRACE), encoding="utf-8")
    (repo / "held_out_case-http_defense-s0.summary.json").write_text(
        json.dumps({"scenario_id": "held_out_case", "defense": "http_defense", "attack_present": True}),
        encoding="utf-8",
    )
    roots = [tmp_path / "kit" / "artifacts", tmp_path / "repo" / "artifacts"]
    return TestClient(create_app(roots)), tmp_path


def test_runs_endpoint_lists_runs_from_every_artifacts_root(two_roots):
    api, _ = two_roots
    body = api.get("/api/runs").json()
    assert sorted(r["scenario"] for r in body["runs"]) == ["enterprise_poisoned_invoice", "held_out_case"]
    assert len(body["roots"]) == 2


def test_run_endpoint_reads_from_any_artifacts_root(two_roots):
    api, _ = two_roots
    runs = {r["scenario"]: r["id"] for r in api.get("/api/runs").json()["runs"]}
    body = api.get("/api/run", params={"path": runs["held_out_case"]}).json()
    assert body["summary"]["attack_present"] is True
    assert body["scenario"] == "held_out_case"


def test_run_endpoint_still_refuses_paths_outside_every_root(two_roots):
    api, tmp_path = two_roots
    outside = tmp_path / "loose.jsonl"
    outside.write_text("{}", encoding="utf-8")
    assert api.get("/api/run", params={"path": str(outside)}).status_code == 400


def test_runs_endpoint_reports_when_no_root_exists(tmp_path):
    api = TestClient(create_app([tmp_path / "absent"]))
    body = api.get("/api/runs").json()
    assert body["runs"] == []
    assert body["error"] == "artifacts directory not found"


def test_config_endpoint_serves_the_thresholds_the_engine_decides_with(client):
    """The score bar draws the decision boundaries; they must be the engine's, not a copy."""
    from haris.config import SETTINGS

    api, _ = client
    body = api.get("/api/config").json()
    assert body["thresholds"] == {"escalate": SETTINGS.escalate_threshold, "block": SETTINGS.block_threshold}
    assert body["journals"] and body["roots"]


def test_artifact_roots_parse_from_an_os_path_list(tmp_path, monkeypatch):
    import os

    from dashboard.app import artifact_roots

    monkeypatch.setenv("HARIS_ARTIFACTS", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b"), ""]))
    assert artifact_roots() == [tmp_path / "a", tmp_path / "b"]
