#!/usr/bin/env bash
# Serve the HARIS trace viewer against a kit's artifacts.
# Usage: scripts/run_dashboard.sh <kit_dir> [port]
set -euo pipefail
# shellcheck source=scripts/_uv.sh
. "$(dirname "$0")/_uv.sh"
KIT="${1:?path to Sentinel_Starter_Kit}"
PORT="${2:-8090}"
export HARIS_ARTIFACTS="$KIT/artifacts"
export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
echo "HARIS trace viewer: http://127.0.0.1:$PORT"
$UV run --python 3.12 uvicorn dashboard.app:app --host 127.0.0.1 --port "$PORT"
