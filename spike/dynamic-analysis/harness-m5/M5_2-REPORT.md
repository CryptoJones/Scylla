# Harness M5.2 — benign uplift: a real run merged into the model, `WRONG = 0`: **PASS**

M4 ran the producer end-to-end but couldn't merge into the *sample's own* model without ingesting it.
M5.2 closes that loop **without the engine** by using a real artifact already in the repo: the
`mathlib` fixture (`prototype/corpus/src/mathlib.c`) and its real `crates/scylla-wasm/web/mathlib.scylla`.
A real run's observed call graph merges into that model, confirmed + stamped `producer="dynamic"`, with
`WRONG = 0` preserved.

## What it does (`m5_2-uplift.sh`)

1. Compile `mathlib.c` (`-O0`, the build `mathlib.scylla` models).
2. **Observe the real runtime call graph** with a gdb function-entry tracer (records `caller → callee`
   at runtime — an *uncooperative* internal-call observation; M5.1 proved in-tier uncooperative
   observation, this is the merge it feeds). Internal call edges are the **provenance-carrying**
   observation (DD-007 `EdgeProvenance`, `model.capnp @13`); the resolved-import IAT (M3/M5.1) is the
   complementary half.
3. **Merge** (`spike m5_2 mathlib.scylla edges.json`): resolve each observed `from`/`to` to a `StableId`
   by identity, check it against the static `callees`, and stamp.

## Measured

```
RT_EDGE fib -> fib / main -> factorial / main -> fib / main -> gcd / main -> sum_to   (real run)
[m5.2]   CONFIRM fib -> fib  (existing static edge, now stamped DD-007 Provenance { producer: "dynamic", confidence: 90 })
[m5.2]   CONFIRM main -> {factorial,fib,gcd,sum_to}  (… stamped dynamic …)
[m5.2] confirmed=5  dynamic-only=0  unmatched=0
[m5.2] VERDICT: GO — every observed runtime edge landed on EXISTING function identities … WRONG=0 holds.
```

All 5 observed edges **landed on existing function identities** and **matched the static call graph** —
so they're stamped `producer="dynamic"` (the graph is now *runtime-confirmed*), with **0 unmatched, 0
contradictions = `WRONG = 0`**. The seam uplift the spike predicted, now from a **real contained run**.

## Why this is `WRONG = 0`-safe (and what "uplift" means here)

- M5.2 **consumes** the model; it does not touch `callees` or the re-anchoring matcher. A dynamic
  observation can only **CONFIRM** an existing edge (stamp it) or **ADD** a dynamic-only edge it missed
  (as a sparse `EdgeProvenance` sidecar) — it can **never overwrite or mis-identify**. Endpoints that
  don't resolve to a model identity are reported `unmatched` and **not merged** (never guessed).
- The dynamic stamp is partial-coverage `confidence = 90` (never `user`/100), so even where DD-027
  `collaborate` later weighs it, it can't outrank a confident fact.
- On `mathlib` (a small, fully-static-analyzable program) the static graph was already complete, so the
  uplift is **provenance confirmation** — the call graph is now runtime-evidenced. On a **packed/stripped
  sample** where static analysis leaves edges dangling, the same merge would **ADD** the dynamically
  resolved edges (the seam spike's measured win) — now from a real run, same `WRONG = 0` discipline.

## Scope — the no-malware track is now complete

With M5.2 the **entire benign / no-malware harness track is built and gated**: M1 tier (+ GAP-5/7 red
team) → M2 channel (+ GAP-6 fuzz) → M3 observer → M4 producer → M5.0 Firecracker tier (+ red team) →
M5.1 uncooperative observer → **M5.2 real-run uplift, `WRONG = 0`**. Everything that does not require
real malware is done.

**Only M5.3 / M5.4 remain, and they are a hard infrastructure wall** (per HARNESS-M5-PLAN.md): real
malware on an **isolated node**, with the Firecracker **`jailer`** + a **minimal hardened guest kernel**,
a **malware corpus**, and an **external pen-test**. These need provisioning only the operator can do;
no real malware runs until they exist and GAP-5..9 are re-validated against hostile samples externally.

Reproduce: `./m5_2-uplift.sh` (exit 0 = `WRONG = 0` uplift).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
