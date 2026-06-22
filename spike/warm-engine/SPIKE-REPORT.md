# Spike report — warm co-resident engine (DD-040 de-risk)

**Verdict: GO.** The one risk that could have killed the warm engine — running Ghidra in-process
in the same JVM as grpc-netty-shaded — does **not** materialize. Build it; keep the subprocess as
the fallback per DD-040.

## The question

The engine-service cold-launches `analyzeHeadless` as a **subprocess per Materialize call**
(DD-040), which is clean but pays a fresh JVM + Ghidra application + analyzer/language/decompiler
init *every call*. A warm co-resident engine would keep Ghidra initialized **in-process** and
amortize that. DD-040 deliberately chose the subprocess because *"grpc-java + Netty inside Ghidra's
notoriously fussy plugin classloader is exactly where this design would die"* — and said to
**de-risk with a spike before betting the build.** This is that spike.

## Is the prize real?

Yes. A cold `analyzeHeadless` on `mathlib` (13 functions) is **~6.3 s** on the host (~25 s in the
locked-down container). The analysis of 13 functions is sub-second; the rest is **fixed init** —
JVM start, the Ghidra framework, the SLEIGH language, the decompiler, the analyzer suite — paid
*every call* today and **amortizable by warming**. The framework init alone is ~700 ms (measured
below); the language/decompiler/analyzer init dominate the remainder and warm the same way.

## Is the risk real? (the actual experiment — `Spike.java` / `run-spike.sh`)

One JVM: load grpc-netty-shaded, then `Application.initializeApplication(new GhidraApplicationLayout,
new HeadlessGhidraApplicationConfiguration)` — the classloader-fussy part — then touch grpc again.

```
# default system classloader:
[spike] system classloader = jdk.internal.loader.ClassLoaders$AppClassLoader
[spike] grpc-netty-shaded: loaded OK
[spike] Ghidra in-process init: OK in 697 ms
[spike] RESULT: GO — grpc-netty + in-process Ghidra coexist in ONE JVM (default classloader).
# with GhidraClassLoader as system CL:
[spike] Ghidra in-process init: OK in 712 ms
[spike] RESULT: GO
```

**Both classloader modes work.** Ghidra's app init completes in ~700 ms in a JVM that already has
grpc-netty-shaded loaded — under the *default* `AppClassLoader` and under `GhidraClassLoader`. The
DD-040 nightmare (the classloader fight) does not happen for the headless app.

**The noise, explained.** Init logs a handful of `ClassCastException` at `Class.asSubclass` inside
`performModuleInitialization` — `ClassSearcher` discovering extension points (`TableColumnInitializer`,
`PcodeStateInitializer`, …) it can't cast across classloaders. These are **non-fatal**: init
returns clean, and they are the *same* `ClassSearcher` noise the working subprocess `analyzeHeadless`
already logs (most are GUI/extension classes irrelevant to headless analysis). A warm engine should
quiet them, not fear them.

## What this proves — and what it doesn't

**Proven:** the gating risk. grpc-netty-shaded and an in-process Ghidra **framework** coexist in one
JVM. The classloader is not the blocker DD-040 feared.

**Not yet proven (the implementation, now de-risked):**
- The full in-process **analysis** loop (import + auto-analyze via the headless API, reusing the
  warm language/decompiler). This is standard Ghidra embedding; the spike shows the classloader —
  the scary part — does not stand in its way.
- **Concurrency.** Ghidra analysis is not thread-safe per program; a warm engine needs a serialized
  analysis queue or a small pool of warm contexts, not a free-for-all over concurrent gRPC calls.
- The actual warm-vs-cold speedup end to end (only the ~700 ms framework slice is measured here).

## Recommendation

- **Build it.** Keep one warm Ghidra context in the engine-service JVM; serve `Materialize` from it
  (import + analyze in-process) instead of spawning `analyzeHeadless`. Expected: ~6 s → sub-second
  per call after warm-up on small binaries.
- **Keep the subprocess as the fallback** (DD-040): same RPC, a config flag chooses warm vs
  subprocess. If a hostile binary ever destabilises the warm context, the subprocess path is the
  safety valve — and it's also the only safe option once the *dynamic*-analysis producer exists.
- **First implementation step:** a serialized warm-analysis loop (one context, a request queue),
  measured warm-vs-cold, before any pooling.

## Build outcome — BUILT (everything above proven out)

The build followed the recommendation. Two things the spike left open were settled here:

1. **The OSGi wall.** A Ghidra *script* (compiled via OSGi) **cannot** import `ProgramLoader` /
   `AutoAnalysisManager`, so the in-process analysis loop can't live in `dump_model.java`. It lives
   in a **standalone Java program** instead — `Worker.java` (this dir, the de-risk) and the
   production `engine-service/warm-worker/ScyllaWarmWorker.java` — compiled at startup against the
   mounted dist (like this spike), with **no OSGi limit and no build-coupling** to the ~890MB dist.
2. **The in-process analysis loop.** `ProgramLoader.builder().source(file).project(null).load()` →
   `getPrimaryDomainObject()` → `startTransaction` → `AutoAnalysisManager.initializeOptions()` /
   `reAnalyzeAll(null)` / `startAnalysis(DUMMY)` → `markProgramAnalyzed` → `endTransaction` →
   `lr.close()`. Same extraction as the cold script; same JSON contract.

**Measured, end to end (gRPC → `scylla` CLI → Cap'n Proto artifact), host:**

| call | binary | functions | time |
|------|--------|-----------|------|
| cold subprocess (`analyzeHeadless`) | mathlib | 13 | **6.2 s** |
| warm #1 (first analyze, engine already up) | mathlib | 13 | 3.7 s |
| warm #2 | strutil | 12 | **1.7 s** |
| warm #3 | mathlib | 13 | **2.0 s** |

Warm engine start-up (javac compile + `Application.initializeApplication`): **~1.7 s, paid once.**
The warm artifact is **byte-identical** to the cold one (`cmp` clean, 1072 bytes) — same model, ~3x
faster. **Concurrency** is handled by serializing requests (one warm context, a `synchronized`
materialize); a pool is the noted follow-up. A wedged/failed warm call kills the worker and the RPC
**falls back to the cold subprocess** — the DD-040 safety valve, live. Opt-in via
`SCYLLA_ENGINE_WARM`; default OFF (cold-only stays the proven, dependency-light path).
