#!/usr/bin/env bash
# Prove "a judge can clone this and run it" by actually doing it: clone into a scratch
# directory and sync, test, serve and probe THERE, never touching this working tree.
#
# Why this exists: today's `uv sync --python 3.12` reproduction command (no --all-extras)
# looked fine for weeks, because every checkout that ran it had already been synced once
# with the flag -- the contract package and pytest were already sitting in .venv from an
# earlier, correct sync, so the missing flag installed nothing new and broke nothing
# visible. A judge's `.venv` starts empty. Only a clone with no prior state can catch a
# reproduction command that silently does less than it claims to.
#
# Usage: scripts/verify_clean_clone.sh [source] [kit_dir]
#   source   what to clone: a remote URL, or any local path `git clone` accepts. Defaults
#            to this checkout. A local clone reproduces exactly what the judge's clone
#            would see -- committed state, at HEAD -- which also means uncommitted work
#            in this working tree is invisible to it. That is the point, not a limitation:
#            it is the same blind spot `git push` has, checked before you rely on it.
#   kit_dir  when given, also runs one public scenario from the kit against the clone's
#            served defense, on top of the synthetic probe request.
#
# Cleans up the clone and any server it started on exit, success or failure, and always
# prints one PASS or FAIL line last so a CI log or a human skimming scrollback cannot
# mistake a failure buried above for a pass.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_uv.sh
. "$HERE/_uv.sh"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"
# shellcheck source=scripts/_serve.sh
. "$HERE/_serve.sh"

SOURCE_REPO="${1:-$ROOT}"
KIT="${2:-}"
if [ -n "$KIT" ]; then
  KIT="$(cd "$KIT" && pwd)"
fi

CLONE="$(mktemp -d)"

cleanup() {
  local status=$?
  haris_stop_local
  # `kill` on a native Windows process (what MSYS kill actually sends) can return before
  # the OS has finished tearing the process down, so an `rm -rf` that races right behind it
  # can hit a file still mapped by uvicorn and fail. `set -e` applies inside a trap too, so
  # that failure -- or any other in this function -- would abort before the PASS/FAIL line
  # below ever printed: a real success reported as neither pass nor fail. Wait the process
  # out, and let a still-stubborn rm be non-fatal rather than eat the one line a judge or CI
  # actually reads off this script.
  if [ -n "$HARIS_SERVER_PID" ]; then
    wait "$HARIS_SERVER_PID" 2>/dev/null || true
  fi
  echo ""
  if [ "$status" -eq 0 ]; then
    echo "PASS: a clean clone of $SOURCE_REPO builds, tests, serves, and decides."
  else
    echo "FAIL: a clean clone of $SOURCE_REPO does not work end to end (see above)." >&2
  fi
  rm -rf "$CLONE" || true
  exit "$status"
}
trap cleanup EXIT

echo "==> git clone $SOURCE_REPO -> $CLONE"
git clone --quiet "$SOURCE_REPO" "$CLONE"

echo "==> uv sync --python 3.12 --all-extras"
if ! ( cd "$CLONE" && $UV sync --python 3.12 --all-extras ); then
  echo "FAIL: uv sync could not build the environment in the clean clone." >&2
  echo "  The pinned contract package is fetched from GitHub at sync time (see the" >&2
  echo "  [contract] extra in pyproject.toml); the most likely cause here is no network" >&2
  echo "  reach to it, not a code defect. Either way this must not be reported as a pass." >&2
  exit 1
fi

echo "==> uv run --python 3.12 pytest -q"
if ! ( cd "$CLONE" && $UV run --python 3.12 pytest -q ); then
  echo "FAIL: the test suite does not pass in the clean clone." >&2
  exit 1
fi

echo "==> serving the clean clone and probing it from this host"
haris_serve_local "$CLONE"
if ! haris_preflight "$HARIS_URL"; then
  echo "FAIL: the clean clone's service is not ready, or could not turn the probe request" >&2
  echo "  ($HERE/probe-request.json) into a real decision." >&2
  exit 1
fi
echo "  $HARIS_URL is ready and decided the probe request."

if [ -n "$KIT" ]; then
  scenario="$(find "$KIT/scenarios/public" -type f -name '*.yaml' | sort | head -n 1)"
  if [ -z "$scenario" ]; then
    echo "FAIL: no public scenario found under $KIT/scenarios/public." >&2
    exit 1
  fi
  echo "==> uv run sentinel run --scenario $scenario --defense-url $HARIS_URL"
  # `sentinel run` never raises on an unreachable defense: HttpDefense.decide_or_fallback
  # swallows DefenseUnavailable into a fail-mode decision and the CLI exits 0 regardless,
  # exactly like scripts/_preflight.sh's own incident (91 DefenseUnavailable, official
  # 0.080, exit 0). An exit-code check alone -- what this used to be, output sent to
  # /dev/null -- would pass on that. Capture the JSON and check DecisionRecord.defense_error
  # ourselves, the haris_check_scorecard invariant adapted to a single run.
  run_json="$(cd "$KIT" && $UV run sentinel run --scenario "$scenario" --defense-url "$HARIS_URL" --json)" || {
    echo "FAIL: the kit could not run a real scenario against the clean clone's service." >&2
    exit 1
  }
  if ! printf '%s' "$run_json" | "$_PY" -c '
import json, sys
outcome = json.load(sys.stdin)["outcome"]
decisions = outcome.get("decisions") or []
errored = [d.get("step_id") for d in decisions if d.get("defense_error")]
sys.exit(0 if decisions and not errored else 1)
'; then
    echo "FAIL: the kit ran a scenario, but at least one decision never reached the clean" >&2
    echo "  clone's service (DecisionRecord.defense_error set), or none were recorded at" >&2
    echo "  all. Those numbers would measure the network, not HARIS -- do not report them." >&2
    exit 1
  fi
  echo "  the kit ran $(basename "$scenario") against it end to end; every decision reached it."
fi
