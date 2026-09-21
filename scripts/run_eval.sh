#!/usr/bin/env bash
# Serve HARIS, then score it on a split.
# Usage: scripts/run_eval.sh <kit_dir> [split] [extra sentinel args...]
set -euo pipefail
# shellcheck source=scripts/_uv.sh
. "$(dirname "$0")/_uv.sh"
KIT="${1:?path to Sentinel_Starter_Kit}"
SPLIT="${2:-public}"
shift 2 || true

# Colocate the reasoning journal with the trace artifacts so the dashboard needs one root.
export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"

$UV run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080 --log-level warning &
SERVER=$!
trap "kill $SERVER 2>/dev/null || true" EXIT

for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
  sleep 0.5
done

cd "$KIT"
$UV run sentinel eval "$SPLIT" --defense-url http://127.0.0.1:8080 "$@"
