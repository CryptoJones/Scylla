#!/usr/bin/env bash
# Harness M5.2 — benign UPLIFT: a REAL run's observed call graph merges into the sample's OWN static
# model, with WRONG=0 preserved. Closes M4's loop without the engine: it uses an EXISTING real `.scylla`
# (mathlib, from the prototype corpus) + a REAL observed-edge trace from running the matching binary.
#
# The observer here is a gdb function-entry tracer (records caller->callee at runtime — an *uncooperative*
# internal-call observation; M5.1 proved in-tier uncooperative observation, this is the merge it feeds).
# Internal call edges are the provenance-carrying observation (DD-007 EdgeProvenance, model.capnp @13);
# the resolved-import IAT (M3/M5.1) is the other half. The merge confirms each observed edge against the
# static call graph, stamps producer="dynamic", and proves WRONG=0 (endpoints are existing StableIds;
# `callees` + the matcher are untouched). Still benign; no Scylla core change; real malware is M5.3.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE="$(cd "$HERE/.." && pwd)"; ROOT="$(cd "$SPIKE/../.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}"
GCC="${CC:-/usr/bin/gcc}"
for t in "$GCC" gdb nm; do command -v "$t" >/dev/null || { echo "need $t"; exit 1; }; done
SRC="$ROOT/prototype/corpus/src/mathlib.c"
ART="$ROOT/crates/scylla-wasm/web/mathlib.scylla"
[ -r "$SRC" ] && [ -r "$ART" ] || { echo "need mathlib.c + mathlib.scylla in the repo"; exit 1; }

echo "=== build the spike + compile the real sample (mathlib, the binary mathlib.scylla models) ==="
( cd "$SPIKE" && cargo build -q ) || { echo "spike build failed"; exit 1; }
BIN="$SPIKE/target/debug/dynamic-analysis-seam-spike"
"$GCC" -O0 -o "$W/mathlib" "$SRC"

echo "=== observe the REAL runtime call graph (gdb function-entry tracer; caller->callee) ==="
cat > "$W/gdb-edges.py" <<'PY'
import gdb
edges=set()
class FBP(gdb.Breakpoint):
    def __init__(self, fn):
        super().__init__(fn, gdb.BP_BREAKPOINT, internal=True); self.fn=fn
    def stop(self):
        try: caller=gdb.newest_frame().older().name()
        except Exception: caller=None
        if caller: edges.add((caller, self.fn))
        return False
for fn in ["gcd","fib","factorial","sum_to","main"]:
    try: FBP(fn)
    except Exception: pass
gdb.execute("run 10", to_string=True)
for c,e in sorted(edges): print("RT_EDGE %s -> %s" % (c,e))
gdb.execute("quit")
PY
timeout 40 gdb -q -batch -x "$W/gdb-edges.py" "$W/mathlib" 2>/dev/null | grep RT_EDGE | tee "$W/edges.txt"

echo "=== build the observed-edge trace (JSON) ==="
{ echo '{"edges":['; awk '{print $2, $4}' "$W/edges.txt" | awk 'NR>1{printf ","} {printf "{\"from\":\"%s\",\"to\":\"%s\"}",$1,$2}'; echo ']}'; } > "$W/edges.json"
cat "$W/edges.json"; echo

echo "=== MERGE the real observed edges into mathlib.scylla (confirm + stamp dynamic; WRONG=0) ==="
"$BIN" m5_2 "$ART" "$W/edges.json"
rc=$?
echo "=== m5.2 exit=$rc ==="
exit $rc
