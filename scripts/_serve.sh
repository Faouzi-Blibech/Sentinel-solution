# Serve the HARIS in this checkout on a free loopback port. Source this file.
#
# A fixed 8080 meant that when something else already answered there -- the container
# from run_container.sh, say -- our server failed to bind, died silently, and the run
# scored that other code as this checkout. Every script that serves HARIS locally goes
# through here, so none of them can do that again.
#
# Requires _uv.sh and _preflight.sh to be sourced first.

HARIS_SERVER_PID=""

# haris_serve_local <repo_root>
#   Starts uvicorn, waits for it, and sets HARIS_URL. Exits the script if it dies during
#   startup. The caller must `haris_stop_local` on exit (trap it).
haris_serve_local() {
  local root="${1:?repo root}" port
  port="$("$_PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  HARIS_URL="http://127.0.0.1:$port"
  # Serve from the repo root: uv finds the project by walking up from the working directory.
  ( cd "$root" && exec $UV run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port "$port" --log-level warning ) &
  HARIS_SERVER_PID=$!
  for _ in $(seq 1 120); do
    curl -s -m 2 "$HARIS_URL/healthz" >/dev/null 2>&1 && return 0
    if ! kill -0 "$HARIS_SERVER_PID" 2>/dev/null; then
      echo "the local HARIS server exited during startup; run it by hand to see why:" >&2
      echo "  cd $root && $UV run --python 3.12 uvicorn haris.service:app --port $port" >&2
      exit 1
    fi
    sleep 0.5
  done
}

haris_stop_local() {
  [ -n "$HARIS_SERVER_PID" ] && kill "$HARIS_SERVER_PID" 2>/dev/null || true
}
