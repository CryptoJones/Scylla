# Spike: dynamic-analysis producer — the SEAM (DD-007 / DD-027 candidate)

**Verdict: GO (the seam), with the harness still DEFERRED.** A dynamic producer enriches the same
durable model through the narrow waist, by identity, with no rewrite — proven. Building the thing
that *executes* samples to produce that artifact is a separate, harder project and stays deferred
with its own threat model, exactly as [the eval](../../docs/eval-dynamic-analysis-producer.md)
recommends.

## The one question

The eval deferred the dynamic adapter but named the first real step precisely:

> ingest a single runtime artifact (a resolved IAT from a Scylla dump, or a memory dump of an
> unpacked region) into the model … and merge it against the static model of the same sample.
> **Prove the seam** (as DD-004 re-anchoring and DD-040 gRPC were proven) before betting on the harness.

So the only question here is: **does a second, *dynamic* producer land on the same model — by
identity, no rewrite — the way the static producer does?** Nothing else. This is the de-risk before
the bet, not the bet.

## What this spike does — and pointedly does NOT

- **Does:** loads the static `.scylla` model of a sample, ingests a *resolved IAT* (a list of
  call-sites whose imported targets a dynamic IAT-rebuilder recovered — the RE-scene "Scylla" tool's
  actual job, on a packed/IAT-stripped binary), reconciles it against the static model **by
  `StableId`**, and measures the uplift.
- **Does NOT:** execute any binary, attach to any process, link a debugger, or touch the DD-034
  sandbox. The "runtime artifact" is a committed synthetic fixture (`runtime-iat.json`) standing in
  for the producer's output. **No sample was run.** The execution-containment tier a real dynamic
  producer needs is explicitly out of scope — it is *not* an extension of the parser sandbox and
  gets its own threat model if/when the harness is ever built.

`./run-spike.sh` builds the Rust merge (`src/main.rs`, an isolated `[workspace]` crate path-depending
on `scylla-port` + `scylla-model`) and prints the `[dyn]` lines.

## Measurement (committed `mathlib` fixture)

```
static model:  13 functions, 4 imports known
  (main → [atoi, printf], _start → [__libc_start_main], _init → [__gmon_start__])
runtime IAT:   6 resolved import edges (synthetic, packed-build stand-in)

merge result:
  newly-resolved imports:   5   across 5 functions (main, gcd, fib, factorial, sum_to)
  already known statically: 1   (main → printf — the merge DEDUPES against static knowledge)
  unmatched call-sites:     0   (every IAT entry resolved to an existing StableId)
```

## What the seam proved

1. **Identity holds.** All 6 IAT entries resolved to existing `StableId`s (0 unmatched). The dynamic
   producer enriched the *same* model — it did not fork a parallel one or mint duplicate nodes. This
   is the same property DD-004 re-anchoring and DD-040 gRPC each had to demonstrate; the narrow waist
   absorbed a second producer without noticing.
2. **Measurable uplift.** +5 imports the static analysis never had — and the merge *dedupes* against
   what static already knew (the 1 already-known `printf`), so a real ingest accumulates, it doesn't
   double-count.
3. **It feeds the matcher, not just the view.** `Function.imports` is a **DD-041 cross-architecture
   ANCHOR** input. On a packed or stripped sample static imports trend toward 0 and the anchor goes
   blind; a dynamic IAT rebuild *restores* them. So a dynamic producer doesn't only add data for a
   human to read — it lifts re-anchoring precisely where the static path is weakest. That is the
   non-obvious payoff, and it earns the adapter its keep.

## Productionization path (no-regret first; the harness last)

The eval's "cheap, no-regret groundwork" is confirmed as the right order:

1. **Producer provenance, first-class (DD-007).** This spike merged in its *own* code without
   touching `scylla-model`, on purpose. To productionize, facts/edges need a `producer` +
   `confidence` stamp so a dynamic import is distinguishable from a static one (and from a user
   fact). Useful for static-only collaboration too — it earns its keep before any dynamic producer.
2. **Coverage- and confidence-aware `collaborate` (DD-027).** The merge here is "add if absent."
   Real reconciliation must weigh a runtime observation (high confidence *that it happened*, partial
   coverage) against a static inference (full coverage, lower confidence on indirect targets). That
   is a real `collaborate` extension, not a one-liner.
3. **Only then, the harness — with its own threat model.** A ptrace/Frida/QEMU (Linux) or scripted
   x64dbg (Windows) producer that *executes* the sample to emit the artifact this spike ingested.
   Execution containment is a categorically harder tier than DD-034; do **not** weaken the parser
   sandbox to "get ready" for it.

## Bottom line

The seam is real and cheap; the producer behind it is real and expensive. Ship the no-regret
provenance/collaborate groundwork whenever a producer (static *or* dynamic) needs it; keep the
execution harness deferred until it's worth its own threat model. We proved ours is worth the name
before building the part that shares it.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
