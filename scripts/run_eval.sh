#!/usr/bin/env bash
# Score HARIS on a split.
#
# Usage: scripts/run_eval.sh <kit_dir> [split] [extra sentinel args...]
#
# By default this serves HARIS locally with uvicorn. Set HARIS_URL to score a service that
# is already running instead -- the container from scripts/run_container.sh, for example:
#
#   HARIS_URL=http://127.0.0.1:8080 scripts/run_eval.sh <kit_dir> public
#
# Either way the target must pass a preflight from this host before the evaluation starts,
# and the run is rejected afterwards if any decision failed to reach the defense. Without
# those two checks an unreachable service produces a complete, plausible-looking scorecard
# of blocked actions -- official 0.080 -- and exits 0.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_uv.sh
. "$HERE/_uv.sh"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"
KIT="${1:?path to Sentinel_Starter_Kit}"
SPLIT="${2:-public}"
shift 2 || true

if [ -z "${HARIS_URL:-}" ]; then
  # Colocate the reasoning journal with the trace artifacts so the dashboard needs one root.
  export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
  HARIS_URL="http://127.0.0.1:8080"
  $UV run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080 --log-level warning &
  SERVER=$!
  trap 'kill $SERVER 2>/dev/null || true' EXIT
  for _ in $(seq 1 60); do
    curl -sf "$HARIS_URL/healthz" >/dev/null 2>&1 && break
    sleep 0.5
  done
fi

if ! haris_preflight "$HARIS_URL"; then
  echo "refusing to evaluate: $HARIS_URL cannot make a decision from this host." >&2
  exit 1
fi

LOG="$(mktemp)"
( cd "$KIT" && $UV run sentinel eval "$SPLIT" --defense-url "$HARIS_URL" "$@" ) | tee "$LOG"
haris_check_scorecard "$LOG"
