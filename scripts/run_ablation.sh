#!/usr/bin/env bash
# The baseline ladder: every shipped defense and HARIS, on a published split, with our
# held-out scenarios as the out-of-distribution set.
#
# Usage: scripts/run_ablation.sh <kit_dir> [split]
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

KIT="${1:?usage: scripts/run_ablation.sh <kit_dir> [split]}"
KIT="$(cd "$KIT" && pwd)"
SPLIT="${2:-public}"
case "$SPLIT" in
  '' | *[!a-z_]*) echo "split must be a split name such as public or validation, got: $SPLIT" >&2; exit 1 ;;
esac
trap haris_stop_local EXIT

if [ -z "${HARIS_URL:-}" ]; then
  export HARIS_JOURNAL_PATH="$KIT/artifacts/haris/journal.jsonl"
  haris_serve_local "$ROOT"
fi
if ! haris_preflight "$HARIS_URL"; then
  echo "refusing to run: $HARIS_URL cannot make a decision from this host." >&2
  exit 1
fi

# The kit's artifact store creates event files exclusively; start from clean.
ARTIFACTS="$KIT/artifacts/baselines-$SPLIT"
rm -rf "$ARTIFACTS"

( cd "$ROOT" && $UV run --python 3.12 python -m redteam.harness \
  --kit "$KIT" --split "$SPLIT" --defense-url "$HARIS_URL" \
  --ood "$ROOT/redteam/scenarios" --artifacts "$ARTIFACTS" \
  --out "$ROOT/docs/report/ablation-$SPLIT.json" )
