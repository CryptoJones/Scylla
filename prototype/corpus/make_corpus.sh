#!/usr/bin/env bash
# Generates the re-anchoring test-binary corpus (Scylla prototype, Sprint 1).
# Each program is compiled across {arch} x {opt level}. mathlib + mathlib_v2 are
# the perturbed pair (v2 inserts a function); strutil is an independent program.
# Binaries keep symbols (-g, unstripped) so the spike has ground-truth labels.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"; OUT="$HERE/bin"
mkdir -p "$OUT"

declare -A CC=( [x86-64]="gcc" [aarch64]="aarch64-linux-gnu-gcc" )
OPTS=( O0 O2 )
PROGS=( mathlib mathlib_v2 strutil )

n=0
for prog in "${PROGS[@]}"; do
  for arch in "${!CC[@]}"; do
    cc="${CC[$arch]}"
    if ! command -v "$cc" >/dev/null 2>&1; then echo "skip $arch ($cc missing)"; continue; fi
    for opt in "${OPTS[@]}"; do
      out="$OUT/${prog}.${arch}.${opt}.elf"
      "$cc" "-${opt}" -g -no-pie -o "$out" "$SRC/${prog}.c" 2>/dev/null \
        || "$cc" "-${opt}" -g -o "$out" "$SRC/${prog}.c"
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

echo "corpus: $n binaries in $OUT"
