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
# shellcheck source=scripts/_serve.sh
. "$HERE/_serve.sh"

KIT="${1:?usage: scripts/run_eval.sh <kit_dir> [split] [sentinel args...]}"
KIT="$(cd "$KIT" && pwd)"
shift
SPLIT="public"
if [ "$#" -gt 0 ]; then
  SPLIT="$1"
  shift
fi

MARKER="$(mktemp)"
cleanup() {
  haris_stop_local
  rm -f "$MARKER"
}
trap cleanup EXIT

if [ -z "${HARIS_URL:-}" ]; then
  # Colocate the reasoning journal with the trace artifacts so the dashboard needs one root.
  export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
  haris_serve_local "$ROOT"
fi

if ! haris_preflight "$HARIS_URL"; then
  echo "refusing to evaluate: $HARIS_URL cannot make a decision from this host." >&2
  exit 1
fi

touch "$MARKER"
( cd "$KIT" && $UV run sentinel eval "$SPLIT" --defense-url "$HARIS_URL" ${@+"$@"} )
haris_check_scorecard "$KIT" "$MARKER"
