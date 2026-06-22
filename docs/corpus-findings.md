# Corpus validation — Go + 32-bit (DD-041)

The re-anchoring matcher (exact → arch-independent anchor → reciprocal fuzzy → call-graph
propagation) was built and tuned on x86-64/aarch64 C binaries. This expansion pushes it onto two
new axes — **32-bit (i386)** and a **different toolchain entirely (Go)** — to find where it holds and
where it breaks. The point of a validation corpus is to surface the breaks, not to hide them.

Reproduce: `prototype/corpus/make_corpus.sh` builds everything (i386 needs `gcc-multilib`; Go
cross-compiles with no cross-gcc), then `prototype/harness/snapshot.sh <bin> <out.json>`.

## 32-bit (i386) — gated, the matcher generalizes cleanly

Same C source as x86-64, so it reuses the ground-truth function names and lands in the committed
Tier-0 gate (`crates/scylla-merge/tests/reanchor_gate.rs`). Measured, **WRONG = 0 throughout**:

| class | survival | what carries |
|-------|----------|--------------|
| mathlib i386 O0→v2 (edit-32) | **100%** | exact pass — unchanged from x86-64 |
| mathlib i386 O0→O2 (recompile-32) | 40% | `main` (anchor) + `fib` (propagation) |
| mathlib x86-64 → i386 (cross-arch, 64→32) | 40% | `main` (anchor) + `fib` (propagation) |
| strutil i386 O0→O2 (recompile-32) | 25% | `main` (anchor) |

`main`'s string/import set is **identical** across 64- and 32-bit (Jaccard 1.0); `fib` is recursive
on both. The four-pass matcher needed **zero changes** to handle a new ISA width — the arch-
independent design pays off exactly as intended. Floors are ratcheted into the gate.

## Go — Tier-1 (not committed), two findings

Go binaries are static and runtime-heavy: a trivial program is **~1900–3000 functions / ~1.5 MB**
per snapshot — too large for the tiny, every-CI Tier-0 fixtures, so the Go corpus is generated on
demand (`gomath.go` + the recipe are committed; the binaries/snapshots are git-ignored). Measured
with the shipping four-pass matcher:

### Finding 1 — scale robustness: WRONG = 0 at ~3000 functions ✅

`gomath` amd64 O0→O2 (recompile, **3034 → 1943 functions**): recovered `main.main` + `main.fib`,
**WRONG = 0**. The annotated user functions are a needle in a haystack of Go runtime functions, and
the matcher does not produce a single false positive at that scale. The reciprocal-best rule and the
propagation baseline (a candidate must beat the generic-neighbour score) hold up under ~600× the
function count of the C corpus.

### Finding 2 — the DD-041 anchor is C-centric; Go cross-arch recovers 0 ⚠️

`gomath` amd64 → arm64 (cross-arch, ~1900 functions): **0 recovered, WRONG = 0**. The string/import
anchor — the lever that cracks C cross-arch — **does not fire on Go**:

- **Strings.** Go strings are not NUL-terminated C strings; they are `(ptr, len)` slices packed into
  a single read-only blob. Ghidra does not surface them as per-instruction string *references* the
  way it does for C, so `Function.string_refs` comes back empty for `main.main`.
- **Imports.** `fmt.Printf` is not a dynamic-symbol import; it is a direct call into statically-linked
  Go runtime code (often via interface dispatch). There is no imported *name* to key on.

So `main.main` has no arch-independent feature set on Go → no anchor → nothing for propagation to
spread from → 0 cross-arch. Same-arch Go still works (cosine + structure + recursion), but cross-arch
Go is exactly the case that needs a **Go-aware producer** (extract Go's string blob + devirtualize
runtime calls) or the heavier **Ghidra Version Tracking** lever. This is now the concrete motivation
for those, not a hypothetical. WRONG = 0 held even while recovering nothing — the matcher fails
*closed* (flag, never guess), which is the contract.
