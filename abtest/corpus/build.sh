#!/usr/bin/env bash
# Builds the A/B parity corpus (abtest/corpus/bin): the SAME small programs compiled with four
# toolchains — C (gcc), C++ (g++), Go, Rust — at two optimization levels, plus stripped variants.
# C/C++/Go sources are reused from prototype/corpus/src (one source of truth); the Rust sample is
# src/rustmath.rs. Binaries keep symbols unless the name says `.strip`, so the report can name
# functions; the stripped variants prove the wrapper is faithful when the engine has no names.
#
# Deterministic where the toolchain honours it (SOURCE_DATE_EPOCH, no build-id) so a rebuild
# reproduces the committed corpus byte-for-byte on the same toolchain versions.
#
# Toolchain notes (ronin28): `cc` on PATH is a broken wrapper — we call /usr/bin/gcc explicitly.
# GayHydra 26.3's Go analyzer crashes on Go 1.26 binaries (spike/go-producer/SPIKE-REPORT.md), so
# the Go corpus is built with the go1.22.0 toolchain (GOTOOLCHAIN); one Go 1.26 build is kept ON
# PURPOSE to document that known engine limitation in the report.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CSRC="$REPO/prototype/corpus/src"
RSRC="$HERE/src"
OUT="$HERE/bin"
mkdir -p "$OUT"

export SOURCE_DATE_EPOCH=1500000000
GCC="${GCC:-/usr/bin/gcc}"
GXX="${GXX:-/usr/bin/g++}"
RUSTC="${RUSTC:-$HOME/.cargo/bin/rustc}"
[ -x "$RUSTC" ] || RUSTC="$(command -v rustc || true)"
GO="${GO:-$(command -v go || true)}"
GO_OLD="${GO_OLD:-go1.22.0}"   # the GayHydra-supported Go toolchain
n=0
built() { echo "built $(basename "$1")  [$(file -b "$1" | cut -d, -f1-2)]"; n=$((n+1)); }
strip_copy() { cp "$1" "$2" && strip --strip-all "$2" && built "$2"; }

# --- C: mathlib + strutil, x86-64 and i386, O0 + O2, a stripped O2 each ---------------------
if [ -x "$GCC" ]; then
  for prog in mathlib strutil; do
    for arch in x86-64 i386; do
      extra=""; [ "$arch" = i386 ] && extra="-m32"
      for opt in O0 O2; do
        out="$OUT/${prog}.c.${arch}.${opt}.elf"
        if ! "$GCC" $extra "-${opt}" -g -no-pie -Wl,--build-id=none -o "$out" "$CSRC/${prog}.c" 2>/dev/null; then
          echo "skip $prog $arch ($GCC $extra failed — gcc-multilib missing?)"; continue
        fi
        built "$out"
        [ "$opt" = O2 ] && strip_copy "$out" "$OUT/${prog}.c.${arch}.${opt}.strip.elf"
      done
    done
  done
else
  echo "skip C ($GCC missing)"
fi

# --- C++: shapes (vtables, mangled names), x86-64, O0 + O2, a stripped O2 -------------------
if [ -x "$GXX" ]; then
  for opt in O0 O2; do
    out="$OUT/shapes.cpp.x86-64.${opt}.elf"
    "$GXX" "-${opt}" -g -no-pie -Wl,--build-id=none -o "$out" "$CSRC/shapes.cpp"
    built "$out"
    [ "$opt" = O2 ] && strip_copy "$out" "$OUT/shapes.cpp.x86-64.${opt}.strip.elf"
  done
else
  echo "skip C++ ($GXX missing)"
fi

# --- Go: gomath, amd64, O0 (-N -l) + O2 + stripped O2 on go1.22; one go1.26 O2 --------------
# Built from an EMPTY temp dir: a go.mod anywhere up the tree (there is one in $HOME on ronin28)
# would otherwise pin the toolchain and defeat GOTOOLCHAIN.
gobuild() {  # gobuild <toolchain|""> <out> [go build flags...]
  local tc="$1" out="$2"; shift 2
  ( cd "$(mktemp -d)" && GOTOOLCHAIN="${tc:-auto}" GOOS=linux GOARCH=amd64 CGO_ENABLED=0       "$GO" build -trimpath "$@" -o "$out" "$CSRC/gomath.go" ) && built "$out"
}
if [ -n "$GO" ]; then
  if ( cd "$(mktemp -d)" && GOTOOLCHAIN="$GO_OLD" "$GO" version >/dev/null 2>&1 ); then
    gobuild "$GO_OLD" "$OUT/gomath.go122.amd64.O0.elf" -gcflags='all=-N -l'
    gobuild "$GO_OLD" "$OUT/gomath.go122.amd64.O2.elf"
    gobuild "$GO_OLD" "$OUT/gomath.go122.amd64.O2.strip.elf" -ldflags='-s -w'
  else
    echo "skip Go $GO_OLD (toolchain not available offline)"
  fi
  gover="$(cd "$(mktemp -d)" && "$GO" env GOVERSION | sed 's/^go//; s/\.[0-9]*$//; s/\.//')"   # 1.26.0 -> 126
  gobuild "" "$OUT/gomath.go${gover}.amd64.O2.elf"
else
  echo "skip Go (go missing)"
fi

# --- Rust: rustmath, x86-64, opt-level 0 + 2, a stripped 2 ---------------------------------
if [ -n "$RUSTC" ] && [ -x "$RUSTC" ]; then
  RFLAGS=(--edition 2021 -C linker=/usr/bin/gcc -C link-arg=-Wl,--build-id=none --remap-path-prefix "$RSRC=.")
  "$RUSTC" "${RFLAGS[@]}" -C opt-level=0 -g -o "$OUT/rustmath.rs.x86-64.O0.elf" "$RSRC/rustmath.rs"; built "$OUT/rustmath.rs.x86-64.O0.elf"
  "$RUSTC" "${RFLAGS[@]}" -C opt-level=2 -g -o "$OUT/rustmath.rs.x86-64.O2.elf" "$RSRC/rustmath.rs"; built "$OUT/rustmath.rs.x86-64.O2.elf"
  "$RUSTC" "${RFLAGS[@]}" -C opt-level=2 -C strip=symbols -o "$OUT/rustmath.rs.x86-64.O2.strip.elf" "$RSRC/rustmath.rs"; built "$OUT/rustmath.rs.x86-64.O2.strip.elf"
else
  echo "skip Rust (rustc missing)"
fi

echo "abtest corpus: $n binaries in $OUT"
