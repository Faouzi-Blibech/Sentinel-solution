import subprocess
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
    # A bare "bash" here can resolve to WSL's launcher instead of Git's: CreateProcess (what
    # subprocess.run uses) searches the Windows system directory before PATH for an
    # unqualified name, and System32 carries WSL's bash.exe -- unrelated to and unfixed by
    # shutil.which(), which does its own PATH-only search and lands on the same answer
    # outside an interactive Git Bash session, where Git's usr/bin is never on the system
    # PATH to begin with. Rather than guess which bash a caller's environment hands back,
    # use a form both interoperate on: cwd=ROOT plus a repo-relative POSIX path. WSL's
    # launcher translates the calling process's own working directory into the matching
    # /mnt/... path before running the command; MSYS resolves the same relative path
    # natively. Verified against both bashes on this machine.
    subprocess.run(["bash", "-n", rel], cwd=ROOT, check=True)


def test_manifest_matches_the_required_schema():
    manifest = yaml.safe_load((ROOT / "sentinel-submission.yaml").read_text())
    assert manifest["kind"] == "defense"
    assert manifest["api_version"] == "v1"
    assert 1024 <= manifest["port"] <= 65535
    assert manifest["team"]
    # Every external model and dataset must be declared.
    assert "models" in manifest
    assert "datasets" in manifest
