#!/usr/bin/env bash
# The OUTSIDE leg: run the engine dist's analyzeHeadless DIRECTLY on the host (no Scylla, no
# sandbox) over every corpus binary, with the SAME dump_model.java post-script the engine-service
# uses, so the two legs differ only in the wrapper. Mirrors EngineServer.java's cold-path command
# line exactly (project + -import + -scriptPath + -postScript dump_model.java <out> -deleteProject).
#
#   GHIDRA_DIST=/path/to/ghidra_26.3.0_GayHydra-26.3.0 abtest/scripts/run-outside.sh <out-dir> [bin...]
#
# Writes <out-dir>/<bin>.snapshot.json per binary and, unless NO_DECOMP=1, a second headless pass
# with DumpDecomp.java into <out-dir>/decomp/<bin>.decomp.txt (filtered to user code for Go/Rust).
# ONLY_DECOMP=1 skips the snapshot pass (re-dump decomp alone). Logs land in <out-dir>/log/.
# Exit non-zero if any binary failed on the snapshot pass.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
: "${GHIDRA_DIST:?set GHIDRA_DIST to the unpacked engine dist (dir containing support/analyzeHeadless)}"
HL="$GHIDRA_DIST/support/analyzeHeadless"
[ -x "$HL" ] || { echo "error: $HL not executable" >&2; exit 2; }
OUT="${1:?usage: run-outside.sh <out-dir> [bin...]}"; shift || true
mkdir -p "$OUT/decomp" "$OUT/log"
if [ $# -gt 0 ]; then BINS=("$@"); else BINS=("$REPO"/abtest/corpus/bin/*.elf); fi
SCRIPTS="$REPO/engine-service/scripts"

# User-code filter for the decomp baseline: runtime-heavy toolchains dump only their user code.
decomp_filter() {
  case "$(basename "$1")" in
    gomath.*)   echo "main." ;;
    rustmath.*) echo "rustmath" ;;
    *)          echo "" ;;
  esac
}

fail=0
for bin in "${BINS[@]}"; do
  name="$(basename "$bin")"
  snap="$OUT/$name.snapshot.json"
  if [ "${ONLY_DECOMP:-0}" != 1 ]; then
    proj="$(mktemp -d)"
    t0=$(date +%s)
    if "$HL" "$proj" abtest -import "$bin" -scriptPath "$SCRIPTS" \
          -postScript dump_model.java "$snap" -deleteProject >"$OUT/log/$name.snapshot.log" 2>&1 \
       && [ -s "$snap" ]; then
      echo "outside  $name  $(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['function_count'],'functions')" "$snap")  $(( $(date +%s) - t0 ))s"
    else
      echo "outside  $name  FAILED (see $OUT/log/$name.snapshot.log)"; fail=1
    fi
    rm -rf "$proj"
  fi
  if [ "${NO_DECOMP:-0}" != 1 ]; then
    proj="$(mktemp -d)"; dec="$OUT/decomp/$name.decomp.txt"; flt="$(decomp_filter "$bin")"
    t0=$(date +%s)
    if "$HL" "$proj" abtest -import "$bin" -scriptPath "$HERE" \
          -postScript DumpDecomp.java "$dec" $flt -deleteProject >"$OUT/log/$name.decomp.log" 2>&1 \
       && [ -s "$dec" ]; then
      echo "decomp   $name  $(grep -c '^==== FUNCTION' "$dec") functions  $(( $(date +%s) - t0 ))s"
    else
      echo "decomp   $name  FAILED (see $OUT/log/$name.decomp.log)"
    fi
    rm -rf "$proj"
  fi
done
exit $fail
