#!/usr/bin/env bash
# Serve the HARIS trace viewer against a kit's artifacts and our own red-team runs.
# Usage: scripts/run_dashboard.sh <kit_dir> [port]
set -euo pipefail
# shellcheck source=scripts/_uv.sh
. "$(dirname "$0")/_uv.sh"
KIT="${1:?path to Sentinel_Starter_Kit}"
PORT="${2:-8090}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# The viewer reads a PATH-style list. Python splits it on os.pathsep, which is ';' on
# Windows, and Git Bash only rewrites lists that start with '/', so hand it native paths.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
SEP=":"
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) SEP=";" ;; esac

# Kit evals write under the kit; scripts/run_redteam.sh writes under this repository.
export HARIS_ARTIFACTS="$(native "$KIT/artifacts")${SEP}$(native "$REPO/artifacts")"
# Both journals: the kit's (run_eval.sh and the compose stack write there) and this
# repository's (a HARIS started with a plain `uvicorn` from the repo root writes there).
# Reading only the first showed "No journal" for every run scored against the second.
export HARIS_JOURNAL_PATH="$(native "$KIT/artifacts/haris/journal.jsonl")${SEP}$(native "$REPO/artifacts/haris/journal.jsonl")"
echo "HARIS trace viewer: http://127.0.0.1:$PORT"
cd "$REPO"
$UV run --python 3.12 uvicorn dashboard.app:app --host 127.0.0.1 --port "$PORT"
