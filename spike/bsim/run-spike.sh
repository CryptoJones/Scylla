#!/usr/bin/env bash
# BSim de-risk spike runner (DD-044 candidate). Compiles + runs ScyllaBsimSpike.java against the
# GayHydra dist jars and measures cross-arch (x86-64 <-> aarch64) BSim function similarity on the
# mathlib symmetric leaves (gcd/factorial/sum_to) the four-pass matcher can't re-anchor. Prints the
# [bsim] lines (matrix + verdict). Defaults to the committed O0 cross-arch leaf pair.
#
# Usage: run-spike.sh [sourceBinary] [destBinary]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GH="${GHIDRA_DIST:-/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0}"
SRC="${1:-$ROOT/prototype/corpus/bin/mathlib.x86-64.O0.elf}"
DST="${2:-$ROOT/prototype/corpus/bin/mathlib.aarch64.O0.elf}"

[ -x "$GH/support/analyzeHeadless" ] || { echo "set GHIDRA_DIST to the GayHydra dist"; exit 1; }
[ -f "$SRC" ] && [ -f "$DST" ] || { echo "missing leaf binaries: $SRC / $DST"; exit 1; }

CP="$(find "$GH" -name '*.jar' | tr '\n' ':')"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
javac -proc:none -cp "$CP" -d "$OUT" "$HERE/ScyllaBsimSpike.java"

LOG="$OUT/run.log"
set +e
java -cp "$OUT:$CP" -Dghidra.install.dir="$GH" \
  -Djava.system.class.loader=ghidra.GhidraClassLoader \
  ScyllaBsimSpike "$SRC" "$DST" >"$LOG" 2>&1
rc=$?
set -e

grep '\[bsim\]' "$LOG" || true
if ! grep -q '\[bsim\] GATED' "$LOG"; then
  echo "--- spike did not complete (rc=$rc); tail of log: ---"
  tail -40 "$LOG"
  exit 1
fi
