# Prove, from THIS host, that a HARIS service can actually decide. Source this file.
#
# Why this exists: a Docker Desktop port forward died between two commands, and the next
# evaluation ran for ten minutes producing 91 DefenseUnavailable errors and an official
# score of 0.080 -- while the container itself reported healthy the whole time, because its
# HEALTHCHECK runs *inside* the container and never crosses the broken forward.
#
# So readiness has to be checked from where the simulator stands, and it has to check a
# real decision rather than an open socket:
#   1. /healthz answers from the host and reports ready=true (the contract imports)
#   2. /v1/decision answers a real request with a real verdict, not the internal-error
#      fallback that a missing dependency produces

_PY="$(command -v python3 || command -v python)"
_PROBE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probe-request.json"

# haris_preflight <base_url> -- exit 0 if the service can decide, 1 with a diagnosis if not.
haris_preflight() {
  local url="${1:?base url}"
  local health decision

  if ! health="$(curl -s -m 5 "$url/healthz")"; then
    echo "preflight: nothing answered at $url from this host." >&2
    echo "           If this is a container, its published port is not forwarding; see scripts/run_container.sh." >&2
    return 1
  fi
  if ! echo "$health" | "$_PY" -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("ready") else 1)' 2>/dev/null; then
    echo "preflight: $url is up but NOT ready: $health" >&2
    return 1
  fi

  if ! decision="$(curl -s -m 5 -X POST "$url/v1/decision" -H 'content-type: application/json' -d @"$_PROBE")"; then
    echo "preflight: /healthz answered but /v1/decision did not." >&2
    return 1
  fi
  if ! echo "$decision" | "$_PY" -c '
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

# haris_check_scorecard <eval_output_file> -- fail loudly if the defense was unreachable.
# The kit reports defense errors in its summary table but still exits 0, so a run where
# nothing reached the defense looks like a run where the defense is terrible.
haris_check_scorecard() {
  local log="${1:?eval output}"
  local errors
  errors="$(grep -E 'defense errors' "$log" | grep -oE '[0-9]+' | tail -1)"
  if [ -n "$errors" ] && [ "$errors" -gt 0 ]; then
    echo "" >&2
    echo "INVALID RUN: $errors decisions never reached the defense (DefenseUnavailable)." >&2
    echo "These numbers measure the network, not HARIS. Do not report them." >&2
    echo "If the target was a container, restart it: scripts/run_container.sh" >&2
    return 1
  fi
  return 0
}
