#!/usr/bin/env bash
# Build and run the HARIS container, and do not return until it provably serves decisions
# from this host.
#
# Usage: scripts/run_container.sh [port]          (default 8080)
#        REBUILD=1 scripts/run_container.sh       force a fresh image
#
# Two things this does that `docker run -p 8080:8080` does not:
#
# 1. It publishes on 127.0.0.1 only. A bare `-p 8080:8080` binds every interface, which
#    on a laptop puts the defense on the local network for anyone to call.
#
# 2. It verifies from the host, and recovers. The container's own HEALTHCHECK runs inside
#    the container, so it stays green when the Windows-to-container port forward dies --
#    which is exactly what happened to us once, right after Docker Desktop started. Here a
#    dead forward is detected in seconds and fixed by recreating the container, which gives
#    it a fresh forward.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"

PORT="${1:-8080}"
IMAGE="${IMAGE:-haris:local}"
NAME="${NAME:-haris}"
ATTEMPTS="${ATTEMPTS:-3}"
URL="http://127.0.0.1:$PORT"

if ! docker info >/dev/null 2>&1; then
  echo "Docker engine is not reachable. Start Docker Desktop and wait for it to say 'Engine running'." >&2
  exit 1
fi

if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE ..."
  docker build -t "$IMAGE" "$HERE/.." >/dev/null
fi

for attempt in $(seq 1 "$ATTEMPTS"); do
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if ! run_error="$(docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" "$IMAGE" 2>&1 >/dev/null)"; then
    echo "could not start the container on port $PORT:" >&2
    echo "  $run_error" >&2
    echo "Another process probably holds that port. Pick another: scripts/run_container.sh 8090" >&2
    exit 1
  fi

  # Give uvicorn time to bind before judging the forward.
  for _ in $(seq 1 30); do
    curl -s -m 2 "$URL/healthz" >/dev/null 2>&1 && break
    sleep 1
  done

  if haris_preflight "$URL"; then
    echo "HARIS is serving decisions at $URL  (container: $NAME, attempt $attempt/$ATTEMPTS)"
    echo "  score it:  HARIS_URL=$URL scripts/run_eval.sh <kit_dir> public"
    echo "  stop it:   docker rm -f $NAME"
    exit 0
  fi

  echo "attempt $attempt/$ATTEMPTS: container not reachable from this host; recreating it." >&2
  if docker inspect "$NAME" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    echo "  (the container is running -- the port forward is what failed, not HARIS)" >&2
  else
    echo "  (the container stopped; its last log lines:)" >&2
    docker logs --tail 15 "$NAME" >&2 || true
  fi
done

echo "HARIS did not become reachable at $URL after $ATTEMPTS attempts." >&2
echo "Check that nothing else holds port $PORT, or restart Docker Desktop." >&2
exit 1
