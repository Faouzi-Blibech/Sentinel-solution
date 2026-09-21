# Prove, from THIS host, that a HARIS service can actually decide. Source this file.
#
# Why this exists: a Docker Desktop port forward died between two commands, and the next
# evaluation ran for ten minutes producing 91 DefenseUnavailable errors and an official
# score of 0.080 -- while the container reported healthy the whole time, because its
# HEALTHCHECK runs inside the container and never crosses the broken forward.
#
# Readiness is checked from where the simulator stands, and on a real decision rather than
# an open socket.

_PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
_PROBE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probe-request.json"

_need_python() {
  if [ -z "$_PY" ]; then
    echo "preflight: no python3 or python on PATH; it is needed to read JSON responses." >&2
    return 1
  fi
}

# haris_preflight <base_url>
#   0  the service answers and makes a real decision
#   2  nothing answers at that address        -- a transport fault; recreating can fix it
#   1  it answers but cannot decide           -- a HARIS fault; recreating the same image cannot
haris_preflight() {
  local url="${1:?base url}"
  local health decision
  _need_python || return 1

  if ! health="$(curl -s -m 5 "$url/healthz")"; then
    echo "preflight: nothing answered at $url from this host." >&2
    return 2
  fi
  if ! printf '%s' "$health" | "$_PY" -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("ready") else 1)' 2>/dev/null; then
    echo "preflight: $url answered but is NOT ready: $health" >&2
    return 1
  fi
  if ! decision="$(curl -s -m 5 -X POST "$url/v1/decision" -H 'content-type: application/json' -d @"$_PROBE")"; then
    echo "preflight: /healthz answered but /v1/decision did not." >&2
    return 2
  fi
  if ! printf '%s' "$decision" | "$_PY" -c '
import json, sys
body = json.load(sys.stdin)
ok = body.get("decision") in {"allow", "block", "escalate", "rewrite"}
sys.exit(0 if ok and "HARIS_INTERNAL_ERROR" not in body.get("reason_codes", []) else 1)
' 2>/dev/null; then
    echo "preflight: /v1/decision returned the fallback, not a decision: $decision" >&2
    return 1
  fi
  return 0
}

# haris_check_scorecard <kit_dir> <marker_file>
# Reject a run in which any decision failed to reach the defense. Reads the scorecard JSON
# the kit writes -- not its printed table, which changes with --json and whose file path
# the console wraps across lines -- choosing the newest scorecard written after <marker>.
# A scorecard that cannot be found is a failure to verify, never a silent pass.
haris_check_scorecard() {
  local kit="${1:?kit dir}" marker="${2:?marker file}"
  _need_python || return 1
  "$_PY" - "$kit/artifacts/scorecards" "$marker" <<'PY'
import json, os, sys
folder, marker = sys.argv[1], sys.argv[2]
since = os.path.getmtime(marker)
fresh = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".json")] if os.path.isdir(folder) else []
fresh = [p for p in fresh if os.path.getmtime(p) >= since]
if not fresh:
    sys.exit("\nCOULD NOT VERIFY: no scorecard was written by this run, so these numbers are unchecked.")
card = json.load(open(max(fresh, key=os.path.getmtime), encoding="utf-8"))
errors = (card.get("metrics") or {}).get("defense_errors")
if errors is None:
    sys.exit("\nCOULD NOT VERIFY: the scorecard has no defense_errors field.")
if errors > 0:
    sys.exit(
        f"\nINVALID RUN: {errors} decisions never reached the defense (DefenseUnavailable).\n"
        "These numbers measure the network, not HARIS. Do not report them.\n"
        "If the target was a container, restart it: scripts/run_container.sh"
    )
PY
}
