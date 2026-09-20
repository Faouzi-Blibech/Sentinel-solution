from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_declares_a_non_root_user():
    text = (ROOT / "Dockerfile").read_text()
    users = [line.split()[1] for line in text.splitlines() if line.strip().upper().startswith("USER ")]
    assert users, "submission validator fails without a USER instruction"
    assert users[-1].split(":")[0] not in {"root", "0"}


def test_dockerfile_has_no_privileged_references():
    text = (ROOT / "Dockerfile").read_text()
    assert "docker.sock" not in text
    assert "--privileged" not in text


def test_manifest_matches_the_required_schema():
    manifest = yaml.safe_load((ROOT / "sentinel-submission.yaml").read_text())
    assert manifest["kind"] == "defense"
    assert manifest["api_version"] == "v1"
    assert 1024 <= manifest["port"] <= 65535
    assert manifest["team"]
    # Every external model and dataset must be declared.
    assert "models" in manifest
    assert "datasets" in manifest
