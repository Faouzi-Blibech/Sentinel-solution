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
  rm -rf "$CLONE"
  echo ""
  if [ "$status" -eq 0 ]; then
    echo "PASS: a clean clone of $SOURCE_REPO builds, tests, serves, and decides."
  else
    echo "FAIL: a clean clone of $SOURCE_REPO does not work end to end (see above)." >&2
  fi
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
  if ! ( cd "$KIT" && $UV run sentinel run --scenario "$scenario" --defense-url "$HARIS_URL" --json >/dev/null ); then
    echo "FAIL: the kit could not run a real scenario against the clean clone's service." >&2
    exit 1
  fi
  echo "  the kit ran $(basename "$scenario") against it end to end."
fi
