#!/usr/bin/env bash
# Generates the re-anchoring test-binary corpus (Scylla prototype, Sprint 1).
# Each program is compiled across {arch} x {opt level}. mathlib + mathlib_v2 are
# the perturbed pair (v2 inserts a function); strutil is an independent program.
# Binaries keep symbols (-g, unstripped) so the spike has ground-truth labels.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"; OUT="$HERE/bin"
mkdir -p "$OUT"

# i386 (32-bit x86) via `gcc -m32` (needs gcc-multilib) — the DD-041 "32-bit" corpus: a different
# ISA width from x86-64 but the SAME C source, so it reuses the ground-truth function names.
declare -A CC=( [x86-64]="gcc" [aarch64]="aarch64-linux-gnu-gcc" [i386]="gcc" )
declare -A CFLAGS=( [x86-64]="" [aarch64]="" [i386]="-m32" )
OPTS=( O0 O2 )
PROGS=( mathlib mathlib_v2 strutil )

n=0
for prog in "${PROGS[@]}"; do
  for arch in "${!CC[@]}"; do
    cc="${CC[$arch]}"; extra="${CFLAGS[$arch]:-}"
    if ! command -v "$cc" >/dev/null 2>&1; then echo "skip $arch ($cc missing)"; continue; fi
    for opt in "${OPTS[@]}"; do
      out="$OUT/${prog}.${arch}.${opt}.elf"
      "$cc" $extra "-${opt}" -g -no-pie -o "$out" "$SRC/${prog}.c" 2>/dev/null \
        || "$cc" $extra "-${opt}" -g -o "$out" "$SRC/${prog}.c"
      echo "built $(basename "$out")  [$(file -b "$out" | cut -d, -f1-2)]"
      n=$((n+1))
    done
  done
done
# C++ (DD-037 Tier-1): mangled names + vtables. aarch64-g++ usually absent -> skipped.
declare -A CXX=( [x86-64]="g++" [aarch64]="aarch64-linux-gnu-g++" )
CPPPROGS=( shapes )
for prog in "${CPPPROGS[@]}"; do
  for arch in "${!CXX[@]}"; do
    cxx="${CXX[$arch]}"
    if ! command -v "$cxx" >/dev/null 2>&1; then echo "skip $arch C++ ($cxx missing)"; continue; fi
    for opt in "${OPTS[@]}"; do
      out="$OUT/${prog}.${arch}.${opt}.elf"
      "$cxx" "-${opt}" -g -no-pie -o "$out" "$SRC/${prog}.cpp" 2>/dev/null \
        || "$cxx" "-${opt}" -g -o "$out" "$SRC/${prog}.cpp"
      echo "built $(basename "$out")  [$(file -b "$out" | cut -d, -f1-2)]"
      n=$((n+1))
    done
  done
done

# Go (DD-041): a static, runtime-heavy binary (~1900 functions) — the scale + different-toolchain
# test. Go cross-compiles with no cross-gcc. "O0" = -gcflags 'all=-N -l' (no opt, no inline); "O2" =
# default (optimized). gomath marks the leaves //go:noinline so they survive as real functions.
# These snapshots are LARGE (~1.5MB) — Tier-1 (generated on demand), not the tiny committed Tier-0.
if command -v go >/dev/null 2>&1; then
  for goarch in amd64 arm64; do
    for opt in O0 O2; do
      out="$OUT/gomath.${goarch}.${opt}.elf"
      if [ "$opt" = O0 ]; then
        GOOS=linux GOARCH="$goarch" go build -gcflags='all=-N -l' -o "$out" "$SRC/gomath.go"
      else
        GOOS=linux GOARCH="$goarch" go build -o "$out" "$SRC/gomath.go"
      fi
      echo "built $(basename "$out")  [$(file -b "$out" | cut -d, -f1-2)]"
      n=$((n+1))
    done
  done
else
  echo "skip Go (go missing)"
fi

echo "corpus: $n binaries in $OUT"
