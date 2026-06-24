#!/usr/bin/env bash
# Harness M5.2 (persist) — prove the dynamic provenance is DURABLE: write the enriched `.scylla` and
# show the DD-007 per-edge provenance (model.capnp @13) survives the Cap'n Proto round-trip.
#
# M5.2 (m5_2-uplift.sh) merged a real run's observed call graph into the model and reported WRONG=0,
# but read-only. This WRITES the enriched artifact and reloads it, confirming the call edges still
# carry producer="dynamic" — so a dynamic producer's observations persist in the durable model,
# additively (legacy artifacts unaffected). Benign; no engine; no Scylla core change.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE="$(cd "$HERE/.." && pwd)"; ROOT="$(cd "$SPIKE/../.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}"
GCC="${CC:-/usr/bin/gcc}"
for t in "$GCC" gdb; do command -v "$t" >/dev/null || { echo "need $t"; exit 1; }; done
SRC="$ROOT/prototype/corpus/src/mathlib.c"; ART="$ROOT/crates/scylla-wasm/web/mathlib.scylla"
[ -r "$SRC" ] && [ -r "$ART" ] || { echo "need mathlib.c + mathlib.scylla"; exit 1; }

echo "=== build spike + sample, observe the real call graph (gdb), build the edge trace ==="
( cd "$SPIKE" && cargo build -q ) || { echo "spike build failed"; exit 1; }
BIN="$SPIKE/target/debug/dynamic-analysis-seam-spike"
"$GCC" -O0 -o "$W/mathlib" "$SRC"
cat > "$W/gdb-edges.py" <<'PY'
import gdb
edges=set()
class FBP(gdb.Breakpoint):
    def __init__(self, fn): super().__init__(fn, gdb.BP_BREAKPOINT, internal=True); self.fn=fn
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
timeout 40 gdb -q -batch -x "$W/gdb-edges.py" "$W/mathlib" 2>/dev/null | grep RT_EDGE > "$W/edges.txt"
{ echo '{"edges":['; awk '{print $2,$4}' "$W/edges.txt" | awk 'NR>1{printf ","}{printf "{\"from\":\"%s\",\"to\":\"%s\"}",$1,$2}'; echo ']}'; } > "$W/edges.json"

echo "=== PERSIST: stamp the edges producer=dynamic, write enriched.scylla, round-trip verify ==="
"$BIN" m5_2-persist "$ART" "$W/edges.json" "$W/enriched.scylla"
rc=$?

echo "=== the enriched artifact is a VALID .scylla (loads through the real CLI) ==="
SCYLLA="$ROOT/target/release/scylla"; [ -x "$SCYLLA" ] || SCYLLA="$ROOT/target/debug/scylla"
if [ -x "$SCYLLA" ]; then
  "$SCYLLA" info "$W/enriched.scylla" && echo "[m5.2-persist] enriched artifact loads cleanly (additive; legacy readers unaffected)."
else
  echo "(scylla CLI not built; skipping the external load check — the round-trip already proved validity)"
fi
echo "=== m5.2-persist exit=$rc ==="
exit $rc
