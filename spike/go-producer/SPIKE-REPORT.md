# Spike report — Go-aware producer (DD-043 de-risk)

**Verdict: GO** (qualified). The Go cross-arch gap that the corpus validation (PR #21,
`docs/corpus-findings.md`) surfaced — Go binaries recover **0** functions cross-architecture because
the C-centric anchor (NUL-terminated strings + dynamic imports) doesn't fire — has a concrete,
tractable fix: **extract callee NAMES as an arch-independent anchor feature**. Proven on stripped Go:
cross-arch recovery goes **0 → 2/4** (`main.main` + `main.fib`), `WRONG = 0`. The one caveat is an
external dependency, not a design flaw (below).

## The questions, answered

**1. Does Ghidra recover Go function names from a STRIPPED binary?** Yes — from `.gopclntab`, which
the Go runtime needs for stack traces and so survives `-ldflags='-s -w' -trimpath`. Measured on
`gomath` built stripped with **Go 1.22**: of 1575 functions, **1** was a `FUN_` placeholder — Ghidra
named essentially everything (`main.fib`, `fmt.Fprintf`, `runtime.convT64`, …) with no symbol table
present. The `GolangSymbolAnalyzer` reads pclntab; stripping the symbol table doesn't blind it.

**2. Are callee-name sets arch-independent?** Yes, exactly. The set of *named functions a function
calls* is identical across amd64 and arm64 (Jaccard **1.00**):

| function | callee-name set (identical amd64 ↔ arm64) |
|----------|-------------------------------------------|
| `main.main` | `fmt.Fprintf`, `strconv.Atoi`, `runtime.convT64`, `runtime.morestack_noctxt`, `main.fib`, `main.factorial`, `main.sumTo` |
| `main.fib`  | `main.fib` (self → recursion), `runtime.morestack_noctxt` |

This is the Go analog of C's imports — and *richer*, because Go statically links the runtime so the
call targets are named (where C's would be a handful of PLT imports). The `GolangStringAnalyzer` also
recovered a Go string (`"sum(%d)=%d\n"`), so Go strings are partially extractable too, but the
callee-name set is the stronger, more complete signal.

**3. Does feeding callee-names to the anchor pass recover Go cross-arch?** Yes. With the anchor set
extended to `string_refs ∪ imports ∪ callee_names`, the four-pass matcher on **stripped** Go 1.22
amd64 → arm64 recovers **2/4** — `main.main` (its 7-name set anchors uniquely) and `main.fib`
(recursion + propagation from `main`) — **WRONG = 0**, up from 0/4. (`main.gcd` is inlined away in the
stripped optimized build, so the denominator is 4, not 5.) Repro: `spike/go-producer/run-spike.sh`.

## The caveat (external, not a blocker)

Ghidra's Go support **lags the Go release**. Go **1.26** (the toolchain on this box) makes the
`GolangSymbolAnalyzer` **crash** — `IOException: InvocationTargetException` in the struct-mapping
markup — because GayHydra 26.3's Go internal-struct definitions don't match Go 1.26's layout yet; it
detects `Go version 1.26.0` and then fails, recovering **0** names. Go **1.22 works perfectly**. So
the producer is viable for Ghidra-supported Go versions; bleeding-edge Go waits on GayHydra's Go
support catching up (an upstream concern, not Scylla's).

## Build path (greenlit by this spike)

1. **Producer** (`ScyllaModel.toJson`): emit a per-function `callee_names` set — the names of called
   functions, **excluding `FUN_*` placeholders** (so it's empty on stripped C, where names don't
   survive, and rich on Go, where pclntab names do). Carry it over the wire + Cap'n Proto like
   `string_refs`/`imports`.
2. **Matcher** (`scylla-merge`): fold `callee_names` into `anchor_set`.
3. **The honesty guard.** Our C gate fixtures are UNSTRIPPED, so their internal callee names
   (`gcd`, `fib`) would let the C gate "cheat" via names a real stripped target wouldn't have — the
   same trap the VT spike flagged for the Symbol Name correlator. Excluding `FUN_*` does NOT fix this
   (unstripped C has real names). Options to keep the gate representative: (a) restrict the anchor's
   callee-name contribution to **inter-package/library** names (Go's `pkg.Func` form — present on
   stripped Go, absent on C); or (b) add **stripped** C fixtures to confirm the feature is inert
   there. Decide at build time; it does not change the GO verdict.
4. **Gate**: a Go cross-arch class. Go snapshots are Tier-1 (~1.5MB), so either commit one stripped
   Go pair as a heavier fixture or gate it out-of-band — same call as the corpus PR.

The Go-aware producer is the cheaper of the two cross-arch levers (the other is BSim); this spike
turns "Go cross-arch is 0" from a dead end into a measured 2/4 with a clear, low-risk build.
