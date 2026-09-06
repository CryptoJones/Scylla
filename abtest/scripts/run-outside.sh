#!/usr/bin/env bash
# The OUTSIDE leg: run the engine dist's analyzeHeadless DIRECTLY on the host (no Scylla, no
# sandbox) over every corpus binary, with the SAME dump_model.java post-script the engine-service
# uses, so the two legs differ only in the wrapper. Mirrors EngineServer.java's cold-path command
# line (project + -import + -scriptPath + -postScript dump_model.java <out> -deleteProject); the
# decomp dump (DumpDecomp.java) rides as a SECOND post-script in the same run — it executes after
# the snapshot file is already written, so the snapshot is exactly what the service would emit.
#
#   GHIDRA_DIST=/path/to/ghidra_26.3.0_GayHydra-26.3.0 abtest/scripts/run-outside.sh <out-dir> [bin...]
#
# Writes <out-dir>/<bin>.snapshot.json per binary and <out-dir>/decomp/<bin>.decomp.txt (filtered to
# user code for Go/Rust). NO_DECOMP=1 skips the decomp post-script (control runs); ONLY_DECOMP=1
# re-dumps decomp alone. JOBS=N runs N binaries concurrently (each is a full JVM; 2-3 is sane on a
# 14 GB box). Logs land in <out-dir>/log/. Exit non-zero if any binary failed on the snapshot pass.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${ABTEST_REPO:-$(cd "$HERE/../.." && pwd)}"
: "${GHIDRA_DIST:?set GHIDRA_DIST to the unpacked engine dist (dir containing support/analyzeHeadless)}"
# Wall-clock bound per headless run (a pathological binary must not hang the leg); the inside leg
# has SCYLLA_ENGINE_TIMEOUT_SEC for the same reason.
TIMEOUT_SEC="${TIMEOUT_SEC:-900}"
HL="$GHIDRA_DIST/support/analyzeHeadless"
[ -x "$HL" ] || { echo "error: $HL not executable" >&2; exit 2; }
OUT="${1:?usage: run-outside.sh <out-dir> [bin...]}"; shift || true
mkdir -p "$OUT/decomp" "$OUT/log"
if [ $# -gt 0 ]; then BINS=("$@"); else BINS=("$REPO"/abtest/corpus/bin/*.elf); fi
SCRIPTS="$REPO/engine-service/scripts"
export HL OUT HERE SCRIPTS TIMEOUT_SEC NO_DECOMP="${NO_DECOMP:-0}" ONLY_DECOMP="${ONLY_DECOMP:-0}"

# User-code filter for the decomp baseline, by toolchain field (<prog>.<tc>.…): runtime-heavy
# toolchains dump only their user code — Go's `main.` package, Rust's crate namespace (= <prog>).
decomp_filter() {
  local name; name="$(basename "$1")"; local prog="${name%%.*}" tc; tc="$(echo "$name" | cut -d. -f2)"
  case "$tc" in
    go*)   echo "main." ;;
    rustc) echo "$prog" ;;
    *)     echo "" ;;
  esac
}
export -f decomp_filter

one() {  # one <bin>  -> prints a status line; exit 1 on snapshot failure
  local bin="$1" name; name="$(basename "$bin")"
  local snap="$OUT/$name.snapshot.json" dec="$OUT/decomp/$name.decomp.txt" flt; flt="$(decomp_filter "$bin")"
  local proj; proj="$(mktemp -d)"; local t0; t0=$(date +%s)
  local args=("$proj" abtest -import "$bin" -scriptPath "$SCRIPTS;$HERE")
  [ "$ONLY_DECOMP" != 1 ] && args+=(-postScript dump_model.java "$snap")
  [ "$NO_DECOMP" != 1 ]   && args+=(-postScript DumpDecomp.java "$dec" $flt)
  args+=(-deleteProject)
  local rc=0
  timeout -k 10 "$TIMEOUT_SEC" "$HL" "${args[@]}" >"$OUT/log/$name.snapshot.log" 2>&1 || rc=$?
  rm -rf "$proj"
  local dt=$(( $(date +%s) - t0 ))
  if [ "$ONLY_DECOMP" != 1 ] && { [ $rc -ne 0 ] || [ ! -s "$snap" ]; }; then
    echo "outside  $name  FAILED (see $OUT/log/$name.snapshot.log)"; return 1
  fi
  local fc="" dc=""
  [ "$ONLY_DECOMP" != 1 ] && fc="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['function_count'])" "$snap") functions"
  if [ "$NO_DECOMP" != 1 ]; then
    if [ -s "$dec" ]; then dc="decomp $(grep -c '^==== FUNCTION' "$dec")"; else dc="decomp FAILED"; fi
  fi
  echo "outside  $name  $fc  $dc  ${dt}s"
}
export -f one

fail=0
if [ "${JOBS:-1}" -gt 1 ]; then
  printf '%s\0' "${BINS[@]}" | xargs -0 -P "$JOBS" -n 1 bash -c 'one "$0"' || fail=1
else
  for bin in "${BINS[@]}"; do one "$bin" || fail=1; done
fi
exit $fail
