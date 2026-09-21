#!/usr/bin/env bash
# Score HARIS on a split.
#
# Usage: scripts/run_eval.sh <kit_dir> [split] [extra sentinel args...]
#
# By default this serves the HARIS in this checkout locally. Set HARIS_URL to score a
# service that is already running instead -- the container, for example:
#
#   HARIS_URL=http://127.0.0.1:8080 scripts/run_eval.sh <kit_dir> public
#
# Either way the target must pass a preflight from this host first, and the run is rejected
# afterwards if any decision failed to reach the defense. Without both checks an
# unreachable service yields a complete, plausible scorecard -- official 0.080 -- and exit 0.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_uv.sh
. "$HERE/_uv.sh"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"

KIT="${1:?usage: scripts/run_eval.sh <kit_dir> [split] [sentinel args...]}"
KIT="$(cd "$KIT" && pwd)"
shift
SPLIT="public"
if [ "$#" -gt 0 ]; then
  SPLIT="$1"
  shift
fi

MARKER="$(mktemp)"
SERVER=""
cleanup() {
  [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null || true
  rm -f "$MARKER"
}
trap cleanup EXIT

if [ -z "${HARIS_URL:-}" ]; then
  # A port nobody holds. A fixed 8080 meant that when something else already answered there
  # -- the container from run_container.sh, say -- our server failed to bind, died
  # silently, and the evaluation scored that other code as this checkout.
  PORT="$("$_PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  HARIS_URL="http://127.0.0.1:$PORT"
  # Colocate the reasoning journal with the trace artifacts so the dashboard needs one root.
  export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
  # Serve from the repo root: uv finds the project by walking up from the working directory.
  ( cd "$ROOT" && exec $UV run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port "$PORT" --log-level warning ) &
  SERVER=$!
  for _ in $(seq 1 120); do
    curl -s -m 2 "$HARIS_URL/healthz" >/dev/null 2>&1 && break
    if ! kill -0 "$SERVER" 2>/dev/null; then
      echo "the local HARIS server exited during startup; run it by hand to see why:" >&2
      echo "  cd $ROOT && $UV run --python 3.12 uvicorn haris.service:app --port $PORT" >&2
      exit 1
    fi
    sleep 0.5
  done
fi

if ! haris_preflight "$HARIS_URL"; then
  echo "refusing to evaluate: $HARIS_URL cannot make a decision from this host." >&2
  exit 1
fi

touch "$MARKER"
( cd "$KIT" && $UV run sentinel eval "$SPLIT" --defense-url "$HARIS_URL" ${@+"$@"} )
haris_check_scorecard "$KIT" "$MARKER"
