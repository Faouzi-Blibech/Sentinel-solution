#!/usr/bin/env bash
# Run the ablation matrix with HARIS live.
# Usage: scripts/run_ablation.sh <kit_dir> [split]
set -euo pipefail
KIT="${1:?path to Sentinel_Starter_Kit}"
SPLIT="${2:-public}"
export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"

python -m uv run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080 --log-level warning &
SERVER=$!
trap "kill $SERVER 2>/dev/null || true" EXIT
for _ in $(seq 1 60); do curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.5; done

python -m uv run --python 3.12 python -m redteam.harness \
  --kit "$KIT" --split "$SPLIT" --defense-url http://127.0.0.1:8080 \
  --ood redteam/scenarios --out "docs/report/ablation-$SPLIT.json"
