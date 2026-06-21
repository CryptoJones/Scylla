#!/usr/bin/env bash
# Scylla prototype — analyze one binary with GayHydra headless and emit a model snapshot.
# Usage: snapshot.sh <binary> [out.json]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="${GHIDRA_DIST:-/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0}"
HEADLESS="$DIST/support/analyzeHeadless"
# dump_model.java is owned by the engine-service now (single source of truth, no drift).
SCRIPTS="$(cd "$HERE/../../engine-service/scripts" 2>/dev/null && pwd || true)"

[ -x "$HEADLESS" ] || { echo "analyzeHeadless not found at $HEADLESS (set GHIDRA_DIST)"; exit 1; }
[ -f "$SCRIPTS/dump_model.java" ] || { echo "dump_model.java not found under $SCRIPTS"; exit 1; }
BIN="${1:?usage: snapshot.sh <binary> [out.json]}"
OUT="${2:-/tmp/$(basename "$BIN").snapshot.json}"

PROJDIR="$(mktemp -d)"
trap 'rm -rf "$PROJDIR"' EXIT
LOG="$(mktemp)"

if "$HEADLESS" "$PROJDIR" scylla_tmp \
      -import "$BIN" \
      -scriptPath "$SCRIPTS" \
      -postScript dump_model.java "$OUT" \
      -deleteProject >"$LOG" 2>&1; then
  echo "snapshot: $OUT"
  grep -E "Scylla:|function_count" "$LOG" || true
else
  echo "headless failed; tail of log:"; tail -25 "$LOG"; exit 1
fi
