#!/usr/bin/env bash
# The real ablation: HARIS with one stage removed at a time, on the held-out set.
#
# Every arm is the same decision code with a different `haris.config.Settings`, so a
# difference between rows is attributable to the stage that was removed. The baseline
# ladder in run_ablation.sh answers a different question -- how HARIS compares with
# other people's defenses -- and the rubric asks for both.
#
# Usage: scripts/run_ablation_stages.sh <kit_dir>
set -euo pipefail
# shellcheck source=scripts/_uv.sh
. "$(dirname "$0")/_uv.sh"
KIT="${1:?path to Sentinel_Starter_Kit}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

# The kit's artifact store creates event files exclusively, so a previous run of the
# same arm makes this abort rather than overwrite. Start each ablation from clean.
rm -rf "$KIT/artifacts/ablation"

$UV run --python 3.12 python -m redteam.harness \
  --kit "$KIT" \
  --scenarios "$HERE/redteam/scenarios" \
  --ablation \
  --artifacts "$KIT/artifacts/ablation" \
  --out "$HERE/docs/report/ablation-stages.json"
