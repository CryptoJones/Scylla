#!/usr/bin/env bash
# Scylla — Go-aware producer de-risk (DD-043). Reproduces the spike: build the gomath corpus program
# STRIPPED with a Ghidra-supported Go toolchain (1.22) for amd64 + arm64, snapshot both, and show
# that adding CALLEE NAMES (which survive stripping via Go's pclntab and are arch-independent) to the
# anchor set recovers Go cross-architecture — 0 -> 2/4, WRONG=0 — where the C-centric anchor gets 0.
#
# Why 1.22 not the host's Go: Ghidra's Go support lags the release; Go 1.26 makes GolangSymbolAnalyzer
# crash (struct layout too new) -> 0 names. 1.22 is recovered cleanly even stripped.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/prototype/corpus/src/gomath.go"
OUT="${TMPDIR:-/tmp}/scylla-go-spike"
mkdir -p "$OUT"

for arch in amd64 arm64; do
  echo "building stripped Go 1.22 $arch ..."
  GOTOOLCHAIN=go1.22.0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags='-s -w' -o "$OUT/gomath.$arch.elf" "$SRC"
  bash "$ROOT/prototype/harness/snapshot.sh" "$OUT/gomath.$arch.elf" "$OUT/gomath.$arch.json" >/dev/null
done

python3 "$HERE/measure_callee_anchor.py" "$OUT/gomath.amd64.json" "$OUT/gomath.arm64.json"
