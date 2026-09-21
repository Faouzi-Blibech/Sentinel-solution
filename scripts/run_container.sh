#!/usr/bin/env bash
# Build and run the HARIS container, and do not return until it provably serves decisions
# from this host.
#
# Usage: scripts/run_container.sh [port]        (default 8080)
#
# Environment: HARIS_IMAGE (default haris:local), HARIS_CONTAINER (default haris). The
# names are prefixed on purpose: a generic NAME or IMAGE inherited from another tool would
# be handed to `docker rm -f`.
#
# What a bare `docker run -p 8080:8080` does not do:
#
# 1. Publish on 127.0.0.1 only. `-p 8080:8080` binds every interface, which on a laptop
#    puts the defense on the local network for anyone to call.
# 2. Serve current code. The image is rebuilt on every run -- the layer cache makes that
#    about a second when nothing changed -- so an edit to src/haris can never be scored
#    under an old image while the script reports "HARIS is serving decisions".
# 3. Verify from the host, and tell the two failures apart. The container's HEALTHCHECK
#    runs inside the container and stays green when the Windows-to-container port forward
#    dies. A dead forward is fixed by recreating the container, which gets a fresh one. A
#    container that answers but cannot decide is a HARIS fault: recreating the same image
#    cannot fix it, so that is reported at once rather than retried.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_preflight.sh
. "$HERE/_preflight.sh"

PORT="${1:-8080}"
IMAGE="${HARIS_IMAGE:-haris:local}"
CONTAINER="${HARIS_CONTAINER:-haris}"
ATTEMPTS="${HARIS_ATTEMPTS:-3}"
URL="http://127.0.0.1:$PORT"

case "$PORT" in
  '' | *[!0-9]*) echo "port must be a number, got: $PORT" >&2; exit 1 ;;
esac

if ! docker info >/dev/null 2>&1; then
  echo "Docker engine is not reachable. Start Docker Desktop and wait for 'Engine running'." >&2
  exit 1
fi

echo "building $IMAGE (cached layers make this fast when nothing changed) ..."
if ! docker build -q -t "$IMAGE" "$HERE/.." >/dev/null; then
  echo "docker build failed; run it without -q to see why: docker build -t $IMAGE ." >&2
  exit 1
fi

for attempt in $(seq 1 "$ATTEMPTS"); do
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if ! run_error="$(docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:8080" "$IMAGE" 2>&1 >/dev/null)"; then
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

  status=0
  haris_preflight "$URL" || status=$?
  if [ "$status" -eq 0 ]; then
    echo "HARIS is serving decisions at $URL  (container: $CONTAINER, attempt $attempt/$ATTEMPTS)"
    echo "  score it:  HARIS_URL=$URL scripts/run_eval.sh <kit_dir> public"
    echo "  stop it:   docker rm -f $CONTAINER"
    exit 0
  fi

  if [ "$status" -eq 1 ]; then
    echo "the container answers but cannot make a decision -- a fault in the image, not the network." >&2
    echo "Recreating it would not help. Its last log lines:" >&2
    docker logs --tail 20 "$CONTAINER" >&2 || true
    exit 1
  fi

  if docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
    echo "attempt $attempt/$ATTEMPTS: running, but unreachable from this host -- the port forward failed. Recreating." >&2
  else
    echo "attempt $attempt/$ATTEMPTS: the container stopped. Its last log lines:" >&2
    docker logs --tail 20 "$CONTAINER" >&2 || true
    exit 1
  fi
done

echo "HARIS did not become reachable at $URL after $ATTEMPTS attempts." >&2
echo "Check that nothing else holds port $PORT, or restart Docker Desktop." >&2
exit 1
