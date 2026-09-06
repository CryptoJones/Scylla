#!/usr/bin/env bash
# Builds the A/B parity corpus (abtest/corpus/bin) as a MULTI-PLATFORM MATRIX — k >= 1024 binaries.
# The point is BREADTH of engine behaviour the wrapper must reproduce (architectures, toolchains,
# optimization levels, PIE, stripping), not program size. The engine (GayHydra headless) analyzes
# every architecture statically on this x86-64 host, so cross-built ELFs are first-class corpus
# members — no need to run them, or to analyze on native hardware.
#
#   C   : {mathlib,mathlib_v2,strutil,constructs,floats}
#         x {gcc/x86-64, clang/x86-64, gcc/i386, clang/i386, gcc/aarch64, gcc/armhf, gcc/riscv64, gcc/ppc64le}
#         x {O0,O1,O2,O3,Os,Og,Ofast} x {pie,nopie} x {-,strip}
#   C++ : {shapes,shapes_eh} x {g++/x86-64, clang++/x86-64, g++/aarch64} x (same opt/pie/strip axes)
#   Go  : {gomath,gostr} x {go1.22 over amd64,arm64,arm,386,ppc64le,riscv64; go1.26 amd64}
#         x {O0 (-N -l), O2} x {-,strip}
#   Rust: {rustmath,ruststr} x {x86-64, aarch64} x {opt 0,1,2,3,s,z} x {panic unwind,abort} x {-,strip}
#
# Name: <prog>.<tc>.<arch>.<opt>.<pie>[.strip].elf     (Go: <prog>.<tc>.<arch>.<opt>[.strip].elf)
#   tc in gcc|clang|gxx|clangxx|go122|go126|rustc ; arch names are the corpus's own (armhf, ppc64le...)
#
# Deterministic where the toolchain honours it (SOURCE_DATE_EPOCH, no build-id, trimmed paths).
# ronin28 notes: `cc` on PATH is a broken wrapper — compilers are named explicitly. g++-multilib is
# NOT installed (it conflicts with the aarch64 cross gcc on Ubuntu), so 32-bit C++ is absent by
# design; 32-bit C is covered via gcc-multilib. floats.c uses __uint128_t, absent on 32-bit clang —
# those few skip cleanly. GayHydra 26.3's Go analyzer fails on Go 1.26 binaries
# (spike/go-producer/SPIKE-REPORT.md); the go126 builds are kept ON PURPOSE to document that.
# Go is built from an EMPTY temp dir — a go.mod up-tree ($HOME has one) would defeat GOTOOLCHAIN.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PSRC="$REPO/prototype/corpus/src"; LSRC="$HERE/src"; OUT="$HERE/bin"
mkdir -p "$OUT"; [ "${CLEAN:-0}" = 1 ] && rm -f "$OUT"/*.elf
export SOURCE_DATE_EPOCH=1500000000
RUSTC="${RUSTC:-$HOME/.cargo/bin/rustc}"; [ -x "$RUSTC" ] || RUSTC="$(command -v rustc || true)"
GO="${GO:-$(command -v go || true)}"; GO_OLD="${GO_OLD:-go1.22.0}"
n=0; skipped=0
built() { n=$((n+1)); [ "${QUIET:-0}" = 1 ] || echo "built $(basename "$1")  [$(file -b "$1" | cut -d, -f1-2)]"; }
strip_tool() { case "$1" in aarch64) echo aarch64-linux-gnu-strip;; armhf) echo arm-linux-gnueabihf-strip;; riscv64) echo riscv64-linux-gnu-strip;; ppc64le) echo powerpc64le-linux-gnu-strip;; *) echo strip;; esac; }
strip_copy() { local st; st="$(strip_tool "$3")"; command -v "$st" >/dev/null 2>&1 || st=strip
  if cp "$1" "$2" && "$st" --strip-all "$2" 2>/dev/null; then built "$2"; else rm -f "$2"; skipped=$((skipped+1)); fi; }
src_of() { if [ -f "$LSRC/$1" ]; then echo "$LSRC/$1"; else echo "$PSRC/$1"; fi; }
OPTS=(O0 O1 O2 O3 Os Og Ofast)

# C / C++ compiler table: "tc:compiler:arch"  (arch drives -m32 and the strip tool)
CC_TABLE=(
  "gcc:/usr/bin/gcc:x86-64"   "clang:/usr/bin/clang:x86-64"
  "gcc:/usr/bin/gcc:i386"     "clang:/usr/bin/clang:i386"
  "gcc:aarch64-linux-gnu-gcc:aarch64" "gcc:arm-linux-gnueabihf-gcc:armhf"
  "gcc:riscv64-linux-gnu-gcc:riscv64" "gcc:powerpc64le-linux-gnu-gcc:ppc64le"
)
CXX_TABLE=(
  "gxx:/usr/bin/g++:x86-64"   "clangxx:/usr/bin/clang++:x86-64"
  "gxx:aarch64-linux-gnu-g++:aarch64"
)
cmatrix() {  # cmatrix <table-name> <prog> <src> [ld...]
  local -n tbl="$1"; local prog="$2" src="$3"; shift 3; local ld=("$@")
  local e tc rest cc arch opt pie
  for e in "${tbl[@]}"; do
    tc="${e%%:*}"; rest="${e#*:}"; cc="${rest%%:*}"; arch="${rest##*:}"
    if ! command -v "$cc" >/dev/null 2>&1 && [ ! -x "$cc" ]; then echo "skip $tc/$arch ($cc missing)"; skipped=$((skipped+1)); continue; fi
    local m=(); [ "$arch" = i386 ] && m=(-m32)
    for opt in "${OPTS[@]}"; do
      for pie in pie nopie; do
        local pf=(-no-pie); [ "$pie" = pie ] && pf=(-fPIE -pie)
        local out="$OUT/$prog.$tc.$arch.$opt.$pie.elf"
        if "$cc" "${m[@]}" "-$opt" -g "${pf[@]}" -Wl,--build-id=none -ffile-prefix-map="$(dirname "$src")=." -o "$out" "$src" "${ld[@]}" 2>/dev/null; then
          built "$out"; strip_copy "$out" "${out%.elf}.strip.elf" "$arch"
        else
          skipped=$((skipped+1))
        fi
      done
    done
  done
}
for prog in mathlib mathlib_v2 strutil constructs floats; do
  if [ "$prog" = floats ]; then cmatrix CC_TABLE "$prog" "$(src_of "$prog.c")" -lm; else cmatrix CC_TABLE "$prog" "$(src_of "$prog.c")"; fi
done
for prog in shapes shapes_eh; do cmatrix CXX_TABLE "$prog" "$(src_of "$prog.cpp")"; done

# Go — arch breadth is free (GOARCH); go1.26 kept amd64-only to document the analyzer crash.
gobuild() { local tc="$1" arch="$2" src="$3" out="$4"; shift 4
  if ( cd "$(mktemp -d)" && GOTOOLCHAIN="${tc:-auto}" GOOS=linux GOARCH="$arch" CGO_ENABLED=0 "$GO" build -trimpath "$@" -o "$out" "$src" ); then built "$out"; else skipped=$((skipped+1)); fi; }
if [ -n "$GO" ]; then
  gover="$(cd "$(mktemp -d)" && "$GO" env GOVERSION | sed 's/^go//; s/\.[0-9]*$//; s/\.//')"
  have_old=0; ( cd "$(mktemp -d)" && GOTOOLCHAIN="$GO_OLD" "$GO" version >/dev/null 2>&1 ) && have_old=1
  for prog in gomath gostr; do
    src="$(src_of "$prog.go")"
    # each entry: "<toolchain>|<tag>|<space-separated arches>"
    for pair in "$GO_OLD|go122|amd64 arm64 arm 386 ppc64le riscv64" "|go$gover|amd64"; do
      tc="${pair%%|*}"; rest="${pair#*|}"; tag="${rest%%|*}"; arches="${rest##*|}"
      if [ -n "$tc" ] && [ $have_old = 0 ]; then echo "skip Go $GO_OLD (offline)"; skipped=$((skipped+1)); continue; fi
      for arch in $arches; do
        for opt in O0 O2; do
          gc=(); [ "$opt" = O0 ] && gc=(-gcflags 'all=-N -l')
          base="$OUT/$prog.$tag.$arch.$opt"
          gobuild "$tc" "$arch" "$src" "$base.elf" "${gc[@]}"
          gobuild "$tc" "$arch" "$src" "$base.strip.elf" "${gc[@]}" -ldflags='-s -w'
        done
      done
    done
  done
else echo "skip Go (go missing)"; skipped=$((skipped+1)); fi

# Rust — x86-64 native + aarch64 (cross linker now present).
if [ -n "$RUSTC" ] && [ -x "$RUSTC" ]; then
  targets="$("$RUSTC" --print target-list 2>/dev/null)"
  for prog in rustmath ruststr; do
    src="$LSRC/$prog.rs"
    for rt in "x86-64|x86_64-unknown-linux-gnu|/usr/bin/gcc" "aarch64|aarch64-unknown-linux-gnu|aarch64-linux-gnu-gcc"; do
      arch="${rt%%|*}"; rest="${rt#*|}"; target="${rest%%|*}"; linker="${rest##*|}"
      if ! grep -qx "$target" <<<"$targets"; then echo "skip rust/$arch (target absent)"; skipped=$((skipped+1)); continue; fi
      RFLAGS=(--edition 2021 --target "$target" -C linker="$linker" -C link-arg=-Wl,--build-id=none --remap-path-prefix "$LSRC=.")
      for opt in 0 1 2 3 s z; do
        for panic in unwind abort; do
          g=(); { [ "$opt" = 0 ] || [ "$opt" = 2 ]; } && [ "$panic" = unwind ] && g=(-g)
          base="$OUT/$prog.rustc.$arch.O$opt.$panic"
          if "$RUSTC" "${RFLAGS[@]}" -C "opt-level=$opt" -C "panic=$panic" "${g[@]}" -o "$base.elf" "$src" 2>/dev/null; then built "$base.elf"; else skipped=$((skipped+1)); continue; fi
          if "$RUSTC" "${RFLAGS[@]}" -C "opt-level=$opt" -C "panic=$panic" -C strip=symbols -o "$base.strip.elf" "$src" 2>/dev/null; then built "$base.strip.elf"; else skipped=$((skipped+1)); fi
        done
      done
    done
  done
else echo "skip Rust (rustc missing)"; skipped=$((skipped+1)); fi

echo "abtest corpus: $n binaries in $OUT ($skipped skipped)"
