#!/usr/bin/env bash
# The INSIDE leg: materialize every corpus binary THROUGH Scylla — the sandboxed engine-service
# (engine-service/run-sandboxed.sh, DD-034: --network none, RO rootfs, caps dropped) over gRPC on
# a Unix socket, consumed by `scylla materialize` into a .scylla artifact. Same GHIDRA_DIST as the
# outside leg, so the only variable is the wrapper.
#
#   GHIDRA_DIST=/path/to/dist abtest/scripts/run-inside.sh <out-dir> [bin...]
#
# Needs: docker + the scylla-engine-service:dev image (engine-service/README.md) and a built
# `scylla` CLI (SCYLLA env, default target/debug/scylla). Writes <out-dir>/<bin>.scylla, logs in
# <out-dir>/log/. Starts the sandbox, runs, then stops it — always, even on failure.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
: "${GHIDRA_DIST:?set GHIDRA_DIST to the unpacked engine dist}"
OUT="${1:?usage: run-inside.sh <out-dir> [bin...]}"; shift || true
mkdir -p "$OUT/log"
if [ $# -gt 0 ]; then BINS=("$@"); else BINS=("$REPO"/abtest/corpus/bin/*.elf); fi
SCYLLA="${SCYLLA:-$REPO/target/debug/scylla}"
[ -x "$SCYLLA" ] || { echo "error: $SCYLLA missing — cargo build -p scylla-cli" >&2; exit 2; }

SOCK_DIR="${SOCK_DIR:-$(mktemp -d)}"
export SOCK_DIR GHIDRA_DIST
# A larger timeout than the service default: Go/Rust binaries carry thousands of functions.
export SCYLLA_ENGINE_TIMEOUT_SEC="${SCYLLA_ENGINE_TIMEOUT_SEC:-900}"
"$REPO/engine-service/run-sandboxed.sh" >"$OUT/log/engine-service.log" 2>&1 &
LAUNCHER=$!
cleanup() {
  # run-sandboxed.sh `exec`s docker run; killing the launcher pid stops the container (--rm).
  kill "$LAUNCHER" 2>/dev/null || true
  # belt and braces: stop any container still holding our socket dir
  docker ps -q --filter "volume=$SOCK_DIR" | xargs -r docker stop >/dev/null 2>&1 || true
  wait "$LAUNCHER" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 120); do [ -S "$SOCK_DIR/engine.sock" ] && break; sleep 1; done
[ -S "$SOCK_DIR/engine.sock" ] || { echo "error: engine socket never appeared; see $OUT/log/engine-service.log" >&2; exit 2; }
sleep 2
echo "engine: unix:$SOCK_DIR/engine.sock ($(basename "$GHIDRA_DIST"))"

fail=0
for bin in "${BINS[@]}"; do
  name="$(basename "$bin")"
  art="$OUT/$name.scylla"
  t0=$(date +%s)
  if "$SCYLLA" materialize "unix:$SOCK_DIR/engine.sock" "$bin" "$art" >"$OUT/log/$name.inside.log" 2>&1 \
     && [ -s "$art" ]; then
    echo "inside   $name  $("$SCYLLA" info --json "$art" | python3 -c "import json,sys;print(json.load(sys.stdin)['functions'],'functions')")  $(( $(date +%s) - t0 ))s"
  else
    echo "inside   $name  FAILED (see $OUT/log/$name.inside.log)"; fail=1
  fi
done
exit $fail
