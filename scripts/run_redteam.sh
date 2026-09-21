#!/usr/bin/env bash
# Run every defense against OUR held-out scenarios. This is the generalization evidence.
#
# Usage: scripts/run_redteam.sh <kit_dir>
#
# Serves this checkout's HARIS on a free port (set HARIS_URL to target a running service
# instead) and refuses to start unless it makes a real decision from this host. The
# harness itself refuses to write a report if any decision then fails to arrive.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_uv.sh
. "$HERE/_uv.sh"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"
# shellcheck source=scripts/_serve.sh
. "$HERE/_serve.sh"

KIT="${1:?usage: scripts/run_redteam.sh <kit_dir>}"
KIT="$(cd "$KIT" && pwd)"
trap haris_stop_local EXIT

if [ -z "${HARIS_URL:-}" ]; then
  export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
  haris_serve_local "$ROOT"
fi
if ! haris_preflight "$HARIS_URL"; then
  echo "refusing to run: $HARIS_URL cannot make a decision from this host." >&2
  exit 1
fi

# The kit's artifact store creates event files exclusively, so a previous run of the same
# arm aborts this one rather than being overwritten. The dashboard reads this directory.
ARTIFACTS="$ROOT/artifacts/redteam-heldout"
rm -rf "$ARTIFACTS"

( cd "$ROOT" && $UV run --python 3.12 python -m redteam.harness \
  --kit "$KIT" --scenarios "$ROOT/redteam/scenarios" --defense-url "$HARIS_URL" \
  --artifacts "$ARTIFACTS" --out "$ROOT/docs/report/ablation-heldout.json" )
