#!/usr/bin/env bash
# The INSIDE leg: materialize every corpus binary THROUGH Scylla — the sandboxed engine-service
# (engine-service/run-sandboxed.sh, DD-034: --network none, RO rootfs, caps dropped) over gRPC on
# a Unix socket, consumed by `scylla materialize` into a .scylla artifact. Same GHIDRA_DIST as the
# outside leg, so the only variable is the wrapper.
#
#   GHIDRA_DIST=/path/to/dist abtest/scripts/run-inside.sh <out-dir> [bin...]
#
# ROBUSTNESS — the sandbox is RESTARTED periodically and on failure. A single long-lived container
# accumulates state in its RAM-backed /tmp (each cold analyzeHeadless leaves cruft) and, after a few
# hundred materializations, the tmpfs fills; GayHydra's per-launch JDK-home -save can no longer write
# its settings and every subsequent launch fails with "no TTY detected" — a cascade that failed ~900
# binaries before this was added. So: restart the container every RESTART_EVERY (default 40) binaries
# for a fresh /tmp, and if a materialization fails, restart once and retry it before recording FAILED.
#
# INSIDE_JOBS=N materializes N binaries concurrently. Correct only at INSIDE_JOBS=1 (the default):
# concurrent cold launches race the JDK -save AND contend for the container's memory/CPU, which makes
# large Go analyses DIVERGE from the host. The restart/retry robustness applies to the serial path;
# concurrency stays best-effort. Keep INSIDE_JOBS=1 unless the engine-service gains per-launch
# XDG_CONFIG_HOME isolation and a per-job memory budget.
#
# Needs: docker + the scylla-engine-service:dev image (engine-service/README.md) and a built
# `scylla` CLI (SCYLLA env, default target/debug/scylla). Writes <out-dir>/<bin>.scylla, logs in
# <out-dir>/log/. Starts the sandbox, runs, then stops it — always, even on failure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${ABTEST_REPO:-$(cd "$HERE/../.." && pwd)}"
: "${GHIDRA_DIST:?set GHIDRA_DIST to the unpacked engine dist}"
OUT="${1:?usage: run-inside.sh <out-dir> [bin...]}"; shift || true
mkdir -p "$OUT/log"
if [ $# -gt 0 ]; then BINS=("$@"); else BINS=("$REPO"/abtest/corpus/bin/*.elf); fi
SCYLLA="${SCYLLA:-$REPO/target/debug/scylla}"
[ -x "$SCYLLA" ] || { echo "error: $SCYLLA missing — cargo build -p scylla-cli" >&2; exit 2; }

SOCK_DIR="${SOCK_DIR:-$(mktemp -d)}"
export SOCK_DIR GHIDRA_DIST
export SCYLLA_ENGINE_TIMEOUT_SEC="${SCYLLA_ENGINE_TIMEOUT_SEC:-900}"
export SCYLLA_ENGINE_COLD_CONCURRENCY="${SCYLLA_ENGINE_COLD_CONCURRENCY:-${INSIDE_JOBS:-1}}"
export SCYLLA_SANDBOX_MEM="${SCYLLA_SANDBOX_MEM:-$(( 2 * ${INSIDE_JOBS:-1} + 2 ))g}"
export SCYLLA_SANDBOX_CPUS="${SCYLLA_SANDBOX_CPUS:-$(( 2 * ${INSIDE_JOBS:-1} ))}"
RESTART_EVERY="${RESTART_EVERY:-40}"
LAUNCHER=""

stop_sandbox() {
  [ -n "$LAUNCHER" ] && kill "$LAUNCHER" 2>/dev/null || true
  docker ps -q --filter "volume=$SOCK_DIR" | xargs -r docker stop -t 2 >/dev/null 2>&1 || true
  [ -n "$LAUNCHER" ] && wait "$LAUNCHER" 2>/dev/null || true
  LAUNCHER=""
  rm -f "$SOCK_DIR/engine.sock" 2>/dev/null || true
}
start_sandbox() {  # start the container and block until the socket is live
  stop_sandbox
  "$REPO/engine-service/run-sandboxed.sh" >>"$OUT/log/engine-service.log" 2>&1 &
  LAUNCHER=$!
  local i
  for i in $(seq 1 120); do [ -S "$SOCK_DIR/engine.sock" ] && break; sleep 1; done
  if [ ! -S "$SOCK_DIR/engine.sock" ]; then
    echo "error: engine socket never appeared; see $OUT/log/engine-service.log" >&2
    return 1
  fi
  sleep 2
}
trap stop_sandbox EXIT

materialize_one() {  # materialize_one <bin> -> 0 ok / 1 fail (no restart here)
  local bin="$1" name; name="$(basename "$bin")"; local art="$OUT/$name.scylla"
  "$SCYLLA" materialize "unix:$SOCK_DIR/engine.sock" "$bin" "$art" >"$OUT/log/$name.inside.log" 2>&1 && [ -s "$art" ]
}
report_ok() {  # report_ok <name> <t0> [suffix]
  echo "inside   $1  $("$SCYLLA" info --json "$OUT/$1.scylla" | python3 -c "import json,sys;print(json.load(sys.stdin)['functions'],'functions')")  $(( $(date +%s) - $2 ))s${3:-}"
}

start_sandbox || exit 2
echo "engine: unix:$SOCK_DIR/engine.sock ($(basename "$GHIDRA_DIST"))  restart-every=$RESTART_EVERY"

# Concurrent path (best-effort, no restart) — kept for INSIDE_JOBS>1; the serial path below is robust.
if [ "${INSIDE_JOBS:-1}" -gt 1 ]; then
  export SCYLLA OUT SOCK_DIR
  one() { local bin="$1" name; name="$(basename "$bin")"; local art="$OUT/$name.scylla"; local t0; t0=$(date +%s)
    if "$SCYLLA" materialize "unix:$SOCK_DIR/engine.sock" "$bin" "$art" >"$OUT/log/$name.inside.log" 2>&1 && [ -s "$art" ]; then
      echo "inside   $name  $("$SCYLLA" info --json "$art" | python3 -c "import json,sys;print(json.load(sys.stdin)['functions'],'functions')")  $(( $(date +%s) - t0 ))s"
    else echo "inside   $name  FAILED (see $OUT/log/$name.inside.log)"; return 1; fi; }
  export -f one
  fail=0
  printf '%s\0' "${BINS[@]}" | xargs -0 -P "$INSIDE_JOBS" -n 1 bash -c 'one "$0"' || fail=1
  exit $fail
fi

# Serial robust path: periodic restart + restart-and-retry-once on failure.
fail=0; i=0
for bin in "${BINS[@]}"; do
  name="$(basename "$bin")"
  if [ "$i" -gt 0 ] && [ $(( i % RESTART_EVERY )) -eq 0 ]; then
    echo "  (restarting sandbox after $i binaries — fresh /tmp)"
    start_sandbox || { echo "inside   $name  FAILED (sandbox restart)"; fail=1; i=$((i+1)); continue; }
  fi
  i=$((i+1))
  t0=$(date +%s)
  if materialize_one "$bin"; then report_ok "$name" "$t0"; continue; fi
  echo "  ($name failed — restarting sandbox and retrying once)"
  if start_sandbox && materialize_one "$bin"; then report_ok "$name" "$t0" " (after restart)"
  else echo "inside   $name  FAILED (see $OUT/log/$name.inside.log)"; fail=1; fi
done
exit $fail
