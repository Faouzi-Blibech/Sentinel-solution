import os
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _bash() -> str:
    """A bash that can actually run the repo's scripts.

    On Windows a bare "bash" is the wrong one twice over: CreateProcess (what
    subprocess.run uses) searches the system directory before PATH, and shutil.which()
    searches PATH, which outside an interactive Git Bash session does not carry Git's
    usr/bin. Both land on System32's bash.exe, the WSL launcher -- which on a machine with
    no distribution installed cannot start anything at all:
    "execvpe(/bin/bash) failed: No such file or directory". That failed this test for
    every Windows developer while passing CI, which is the worst way for a check to rot.
    Git ships the bash these scripts are written for, so find it where git itself lives.
    """
    if os.name != "nt":
        return "bash"
    git = shutil.which("git")
    if git:
        # git.exe sits in bin/ or mingw64/bin/ depending on how PATH found it, so walk up
        # to the installation root rather than assuming a depth.
        for folder in Path(git).resolve().parents[:4]:
            for candidate in (folder / "bin" / "bash.exe", folder / "usr" / "bin" / "bash.exe"):
                if candidate.is_file():
                    return str(candidate)
    return "bash"


def test_dockerfile_declares_a_non_root_user():
    text = (ROOT / "Dockerfile").read_text()
    users = [line.split()[1] for line in text.splitlines() if line.strip().upper().startswith("USER ")]
    assert users, "submission validator fails without a USER instruction"
    assert users[-1].split(":")[0] not in {"root", "0"}


def test_dockerfile_has_no_privileged_references():
    text = (ROOT / "Dockerfile").read_text()
    assert "docker.sock" not in text
    assert "--privileged" not in text


def test_gitignore_covers_the_kit_clone():
    """`git add -A` must never vendor the organizers' kit into our history.

    Sentinel_Starter_Kit/ is a read-only clone that sits inside the checkout so the
    disqualification audit and the eval scripts can find it (docs/KIT_PATH.md); it is not
    ours to commit.
    """
    text = (ROOT / ".gitignore").read_text()
    assert "Sentinel_Starter_Kit/" in text


def test_verify_clean_clone_script_is_executable_and_well_formed():
    """The judge-facing proof script must actually run, not just exist.

    No behavioral test here on purpose: it clones the repo and syncs a fresh venv, which
    is real work with a real network dependency and is what the script itself exists to
    exercise safely (see its own header). This just guards the two ways it could rot
    silently -- losing its execute bit, or a shell syntax error -- without paying for a
    full run on every test invocation.
    """
    rel = "scripts/verify_clean_clone.sh"
    # Python's os.stat() reports a fixed 0o666 for every file on native Windows regardless
    # of the real bit, so it cannot answer "executable" on this platform. git's tracked
    # mode is what a judge's `git clone` actually checks out on any platform -- and the one
    # thing `chmod` on a Windows checkout does not reliably change without
    # `git update-index --chmod=+x` -- so ask that instead of the filesystem.
    tracked = subprocess.run(
        ["git", "ls-files", "-s", rel],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert tracked, f"{rel} is not tracked by git"
    mode = tracked.split()[0]
    assert mode == "100755", f"git will not check this out executable: mode {mode}"
    subprocess.run([_bash(), "-n", rel], cwd=ROOT, check=True)


def test_manifest_matches_the_required_schema():
    manifest = yaml.safe_load((ROOT / "sentinel-submission.yaml").read_text())
    assert manifest["kind"] == "defense"
    assert manifest["api_version"] == "v1"
    assert 1024 <= manifest["port"] <= 65535
    assert manifest["team"]
    # Every external model and dataset must be declared.
    assert "models" in manifest
    assert "datasets" in manifest


def test_the_viewer_image_can_run_the_guard_console():
    """The console on the viewer's "Connect an agent" page runs `haris.guard` in-process.

    The viewer image once carried only `haris/config.py`, so under `docker compose` -- the
    path the README gives a judge -- every console check answered
    "ModuleNotFoundError: No module named 'haris.guard'" while the local viewer worked.
    """
    dockerfile = (ROOT / "dashboard" / "Dockerfile").read_text()
    ignore = (ROOT / "dashboard" / "Dockerfile.dockerignore").read_text().splitlines()
    ref = next(line for line in (ROOT / "Dockerfile").read_text().splitlines() if line.startswith("ARG SENTINEL_REF="))

    assert ref in dockerfile, "the viewer must pin the same contract commit as the defense image"
    assert "sentinel-bench @ git+" in dockerfile, "haris.guard imports the kit's contract types"
    assert "COPY src ./src" in dockerfile, "haris.guard needs the whole decision path, not config.py alone"
    assert "!src/" in ignore, "the build context must carry the package the Dockerfile copies"
