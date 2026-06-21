# Re-anchoring spike — report (2026-06-21)

**Question (DD-004/005):** when a binary is re-analyzed after a change, do an analyst's
facts (renames/types/comments) re-anchor to the right function, or get orphaned — or, worst
of all, **silently mis-attached** to the wrong function?

**Method.** Annotate the source-defined functions in a v1 snapshot, match each to a v2
snapshot **by structure alone** (`harness/reanchor.py`), and grade with ground-truth symbol
names (used only to score — never as a matching signal). The matcher uses mnemonic-mix
cosine + ordered mnemonic-trigram Jaccard + CFG/in/out-degree closeness, excludes identified
runtime/library functions from the candidate pool, and applies a **confidence threshold**:
a best-match below threshold is reported **ORPHAN** (flag for review), not forced.

## Results (threshold 0.55)

| Perturbation class | OK | **WRONG** | ORPHAN | survived |
|---|---|---|---|---|
| same-opt **edit** — mathlib x86 O0 → v2 (insert `lcm`) | 5 | **0** | 0 | **100%** |
| same-opt **edit** — mathlib aarch64 O0 → v2 | 5 | **0** | 0 | **100%** |
| recompile **O0 → O2** — mathlib x86 | 2 | **0** | 3 | 40% |
| recompile **O0 → O2** — strutil x86 | 1 | **0** | 3 | 25% |
| edit + opt — mathlib x86 O0 → v2 O2 | 2 | **0** | 3 | 40% |
| **cross-arch** — mathlib x86 → aarch64 | 0 | **0** | 5 | 0% |

## What this tells us

**The dangerous failure mode is eliminable.** A naive first pass (no threshold, no library
exclusion) produced silent **WRONG** re-anchors — facts mis-attached to the wrong function,
exactly what would make an RE tool untrustworthy. Adding a confidence threshold + library
exclusion drove **WRONG to zero across every class**. Failures now degrade *safely*: an
unmatched fact is flagged for the analyst, never silently moved onto the wrong code. **This
is DD-005's contract made real** — analysis never fights the user.

**The common case is solved.** Same-optimization re-analysis or a minor source edit — by far
the most frequent real scenario (re-run analysis, apply a small patch) — re-anchors at
**100%, zero wrong**. The inserted `lcm` shifted every later function's address and
boundaries and the facts still followed the right entities.

**The hard cases fail safely, and are an *optimization*, not a wall:**
- **O0 → O2** (25–40% recovered, rest orphaned): aggressive optimization changes the
  instruction mix enough that structural confidence drops below threshold. The facts aren't
  lost or corrupted — they're queued for review. Richer signals (byte/p-code patterns) lift
  recovery.
- **Cross-arch** (0% recovered, 100% orphaned): x86 and aarch64 share no opcodes, so only
  call-graph shape survives — too weak alone for leaf functions. Needs **p-code-level**
  (architecture-neutral) signals. Correctly orphans everything rather than guessing.

## Verdict: **GO**

DD-004/005 stand. The keystone risk is retired in its dangerous form: with a confidence
threshold, re-anchoring **never silently mis-attaches** — it either re-anchors correctly or
flags for review. The everyday case is 100%. Raising hard-case *recovery* (turning safe
orphans into correct matches) is an optimization with a clear path:

1. **Evaluate Ghidra Version Tracking** — the mature multi-signal correlator (bytes,
   instruction patterns, combined scorers) — as the production matcher; this harness is its
   regression measure.
2. **P-code-normalized signals** for cross-arch.
3. Expand the corpus: stripped real-world binaries, function split/merge, inlining.

The Sprint-5 merge engine builds on this with confidence: correct re-anchor → merge; low
confidence → surface as a conflict for the analyst (DD-005), never a silent clobber.

## Reproduce

```
prototype/corpus/make_corpus.sh                       # build the corpus
prototype/harness/snapshot.sh <binary> <out.json>     # GayHydra headless -> snapshot
prototype/harness/reanchor.py <v1.json> <v2.json> [label] [threshold]
```
Snapshots used are in `prototype/snapshots/`.
