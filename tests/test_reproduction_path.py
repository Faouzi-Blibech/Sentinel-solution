"""The documented reproduction path must work on a clean machine.

Both guards here exist because of a real failure, not a hypothetical one. Following
`README.md` produced an environment with neither `pytest` nor the contract package, and on
Windows every script died on its first line with "Python was not found". Neither failure
touched `src/haris/`, so the whole suite stayed green through both.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = (ROOT / "scripts" / "_preflight.sh").as_posix()


def _optional_dependencies() -> dict[str, list[str]]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["optional-dependencies"]


def _bash() -> str | None:
    """A bash that can see this repository.

    `shutil.which("bash")` on Windows finds WSL's bash first, and WSL cannot open a `C:/`
    path -- it would report the helper missing and the guards below would pass vacuously.
    A candidate only counts once it has read the file the test is about.
    """
    candidates = [shutil.which("bash")]
    candidates += [
        str(path)
        for path in (
            Path("C:/Program Files/Git/bin/bash.exe"),
            Path("C:/Program Files (x86)/Git/bin/bash.exe"),
        )
        if path.exists()
    ]
    for candidate in candidates:
        if candidate and subprocess.run(
            [candidate, "-c", f'test -f "{HELPER}"'], capture_output=True, cwd=ROOT
        ).returncode == 0:
            return candidate
    return None


BASH = _bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="no bash that can read this checkout")


def _probe(script: str, **env: str) -> dict[str, str]:
    """Run a snippet with the helper sourced, and parse its `KEY=value` lines.

    Everything is decided inside bash. Handing a `/c/...` path back to Windows Python and
    trying to execute it there is how the first version of this test passed vacuously.
    """
    result = subprocess.run(
        [BASH, "-c", script],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={**os.environ, **env},
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    return dict(
        line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line
    )


def test_the_things_the_documented_commands_need_are_extras_not_defaults():
    """Anchors the test below: were these ever moved into `dependencies`, a bare sync
    would be enough and the README would be right again."""
    extras = _optional_dependencies()
    flat = " ".join(dep for deps in extras.values() for dep in deps)
    assert "sentinel-bench" in flat, "the contract package is no longer an extra"
    assert "pytest" in flat, "the test runner is no longer an extra"


def test_every_documented_sync_installs_the_extras_the_next_command_needs():
    """`uv sync` installs `[project.optional-dependencies]` only when asked.

    A bare `uv sync --python 3.12` installed the four base dependencies and stopped. The
    next line of the README then failed with 26 collection errors -- `No module named
    'sentinel'` -- because both the contract and the test runner are extras.
    """
    extras = set(_optional_dependencies())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    syncs = [line.strip() for line in readme.splitlines() if line.strip().startswith("uv sync")]
    assert syncs, "the README no longer documents how to build the environment"
    for line in syncs:
        named = {extra for extra in extras if f"--extra {extra}" in line}
        assert "--all-extras" in line or named == extras, (
            f"documented command installs neither --all-extras nor {sorted(extras)}: {line!r}"
        )


@needs_bash
def test_preflight_rejects_a_python_that_resolves_but_cannot_run(tmp_path: Path):
    """Windows 11's App execution aliases satisfy `command -v` and then refuse to run.

    `command -v python3 || command -v python` therefore selected a stub, and every script
    that sources this helper -- run_eval, run_redteam, run_ablation, run_container -- died
    before it did anything.
    """
    stub_dir = tmp_path / "windowsapps"
    stub_dir.mkdir()
    for name in ("python3", "python", "py"):
        stub = stub_dir / name
        stub.write_text('#!/bin/sh\necho "Python was not found" >&2\nexit 9009\n', encoding="utf-8")
        stub.chmod(0o755)

    # The stubs go first on PATH, exactly where the real aliases sit on a default install.
    out = _probe(
        f'''
        set -e
        STUB="$(cd "$STUB_DIR" && pwd)"
        PATH="$STUB:$PATH"
        printf 'STUB=%s\\n' "$STUB"
        printf 'RESOLVES=%s\\n' "$(command -v python3)"
        . "{HELPER}"
        printf 'PY=%s\\n' "$_PY"
        if "$_PY" -c '' >/dev/null 2>&1; then printf 'RUNS=1\\n'; else printf 'RUNS=0\\n'; fi
        ''',
        STUB_DIR=str(stub_dir),
    )

    stub, resolves, chosen = out["STUB"], out["RESOLVES"], out["PY"]
    # Without this the test could pass because bash never saw the stubs at all.
    assert resolves.startswith(stub + "/"), f"the stub was not on PATH: {resolves!r}"
    assert chosen, "no interpreter was found even though this suite is running under one"
    assert not chosen.startswith(stub + "/"), f"picked the stub that cannot run: {chosen!r}"
    assert out["RUNS"] == "1", f"picked an interpreter that cannot execute: {chosen!r}"


@needs_bash
def test_preflight_still_finds_the_interpreter_this_suite_runs_under():
    out = _probe(f'. "{HELPER}"; printf \'PY=%s\\n\' "$_PY"')
    assert out.get("PY"), f"no python found, but this suite is running on {sys.executable}"
