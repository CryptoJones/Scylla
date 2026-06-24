# Harness M5.2 (persist) — dynamic provenance is DURABLE in the `.scylla`: **PASS**

M5.2 (`m5_2-uplift.sh`) merged a real run's observed call graph into the model and proved `WRONG = 0`,
but *read-only*. This closes the artifact loop: it **writes** the dynamic-enriched `.scylla` and proves
the DD-007 per-edge provenance (`model.capnp @13`) **survives the Cap'n Proto round-trip** — so a
dynamic producer's observations persist in the durable model, additively.

## What it does (`m5_2-persist.sh` + the spike's `m5_2-persist` path)

1. Compile `mathlib` and observe its real runtime call graph (the gdb function-entry tracer from M5.2).
2. `scylla_schema::from_bytes` the real `mathlib.scylla` into a mutable `Program`.
3. For each observed edge, resolve `from`/`to` to `StableId`s by identity and push an
   `EdgeProvenance { target, Provenance { producer: "dynamic", confidence: 90 } }` onto the source
   function's sparse `edge_provenance` sidecar (dedup — never touches `callees`).
4. `scylla_schema::to_bytes` → **write `enriched.scylla`**.
5. **Reload** it (`from_bytes`) and assert every stamped edge still reports `producer = "dynamic"` via
   `Function::edge_provenance_of`.

## Measured

```
[m5.2-persist] stamped 5 edge(s) producer=dynamic, wrote enriched.scylla (5672 bytes); round-trip: 5/5 survived reload; unmatched=0
[m5.2-persist] VERDICT: GO — the DD-007 per-edge provenance (@13) SURVIVED the Cap'n Proto round-trip ... WRONG=0.
# external check:
name: mathlib.x86-64.O0.elf   language: x86:LE:64:default   functions: 13
[m5.2-persist] enriched artifact loads cleanly (additive; legacy readers unaffected).
```

The enriched artifact is **5672 bytes** vs the original **5096** — it carries the new `@13` edge
provenance — and it loads cleanly through the real `scylla` CLI (`info` shows the same 13 functions),
confirming the addition is **additive**: a reader that ignores `@13` sees an unchanged model (DD-002
evolution), and a reader that reads it gets the dynamic stamps. **5/5 stamps survived reload.**

## Why this matters

- **Durability proven end-to-end.** The whole point of DD-007 was that provenance is *first-class* in
  the durable model, not a runtime-only annotation. This shows it: a dynamic producer's observations,
  written to a `.scylla`, come back as `producer = "dynamic"` after a full serialize→deserialize. The
  call graph is now *runtime-evidenced on disk*.
- **`WRONG = 0` + additive.** Only `edge_provenance` (the sparse `@13` sidecar) is written; `callees`
  and the matcher are untouched, and legacy/older readers are unaffected (empty sidecar). A dynamic
  observation can only annotate an existing edge, never alter identity or the call graph.
- **Closes M5.2.** From "observe → merge → report" (read-only) to "observe → merge → **persist →
  reload → stamps survive**". A real, durable, verifiable artifact.

This completes the benign producer story at the artifact level. The remaining work is M5.3/M5.4 (real
malware, the infrastructure wall) plus the syscall-level observer the packing finding identified
(`M5_1-PACKED-FINDING.md`).

Reproduce: `./m5_2-persist.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
