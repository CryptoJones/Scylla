# Re-anchoring spike — interim report (2026-06-21)

**Question (DD-004/005):** when a binary is re-analyzed after a change, do an analyst's
facts (renames/types/comments) re-anchor to the right function, or get orphaned?

**Method.** Annotate the source-defined functions in a v1 snapshot, match each to a v2
snapshot **by structure alone** (`harness/reanchor.py`: mnemonic-mix cosine + basic-block /
callee / caller closeness), and score with the ground-truth symbol names (used only to
grade — never as a matching signal). First-pass, deliberately naive matcher.

## Results

| Perturbation class | Survival |
|---|---|
| same-opt **edit** — mathlib x86 O0 → v2 O0 (insert `lcm`) | **4/5 (80%)** |
| same-opt **edit** — mathlib aarch64 O0 → v2 O0 | **5/5 (100%)** |
| recompile **O0 → O2** — mathlib x86 | 2/5 (40%) |
| recompile **O0 → O2** — strutil x86 | 1/4 (25%) |
| edit + opt — mathlib x86 O0 → v2 O2 | 2/5 (40%) |
| **cross-arch** — mathlib x86 → aarch64 | 3/5 (60%, degenerate) |

## What this tells us

**The thesis holds where it matters most.** The common real case — *re-run analysis, or a
minor source edit at the same optimization level* — already re-anchors at **80–100% with a
trivial matcher**. The inserted `lcm` shifts every later function's address and boundaries,
and the facts still followed the right entities. That's the core DD-004 bet validated.

**The naive matcher is not the answer for the hard classes** — and the failures are mostly
*matcher quality*, not a fundamental wall:

1. **Runtime-stub false matches (artifact).** Most misses anchor to `deregister_tm_clones`
   (a ~5-instruction runtime stub) at a spuriously high score. A mnemonic *histogram* +
   size-closeness lets tiny functions masquerade as small optimized ones. Fix: exclude
   library/runtime functions from the candidate pool, and use **ordered** instruction
   sequences / byte signals instead of a bag-of-mnemonics.
2. **O0 → O2 changes the instruction mix wholesale.** A bag-of-mnemonics cosine degrades
   under optimization. This is the real, hard case and needs richer signals.
3. **Cross-arch erases mnemonics.** x86 vs aarch64 share no opcodes → cosine = 0 → only the
   call-graph terms survive (every match scored 0.40), and leaf functions are
   indistinguishable on graph shape alone. Needs structural/semantic (p-code-level) matching.

## Verdict: **LEAN GO on the thesis, ADJUST the method**

Re-anchoring is tractable — the everyday case works with almost no effort, and the hard
cases fail in *known, addressable* ways rather than fundamentally. The de-risk conclusion is
**don't hand-roll a matcher**:

- **Evaluate Ghidra's Version Tracking next** (the mature, multi-signal correlator — bytes,
  instruction patterns, call graph, combined scorers). The spike's whole point was to find
  out whether to build or borrow; the answer is *borrow and measure*.
- Quick matcher wins to retest first: drop library/runtime functions; add ordered-trigram /
  byte-sequence similarity; p-code-normalized signals for cross-arch.
- Expand the corpus: a stripped real-world binary, more programs, function split/merge cases.

**This does not block the architecture.** DD-004/005 stand; the re-anchoring *engine* (Sprint
5) should be built on Version Tracking, with this harness as its regression measure.

## Reproduce

```
prototype/corpus/make_corpus.sh                       # build the corpus
prototype/harness/snapshot.sh <binary> <out.json>     # GayHydra headless -> snapshot
prototype/harness/reanchor.py <v1.json> <v2.json>     # match + score
```
Snapshots used are in `prototype/snapshots/`.
