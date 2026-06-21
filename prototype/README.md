# Scylla prototype — the keystone de-risk

This directory is **Sprint 1 + Sprint 2** of [../SprintPlanning.md](../SprintPlanning.md):
proving the one assumption the whole platform rests on before any of it is built.

## The question

**DD-004 / DD-005:** when a binary is re-analyzed and its structure shifts (re-compiled,
patched, different analysis settings), can a user's facts — renames, retypes, comments —
**re-anchor to the right entity** instead of being orphaned? If yes, "git for reverse
engineering" (DD-027) and "analysis never fights the user" are real. If no, those decisions
need to change *before* we build a Rust core on top of them.

## The spike (annotate → perturb → re-anchor → measure)

1. **Analyze** a binary with GayHydra headless → a normalized model snapshot.
2. **Annotate** — attach synthetic-ID-keyed user facts (rename / retype / comment).
3. **Perturb** — re-analyze a recompiled / edited variant → a second snapshot whose
   addresses and boundaries have moved.
4. **Re-anchor** — match v2 entities back to v1 IDs via binary-diff signals (call-graph
   position, CFG / p-code fingerprint, decompiled-text similarity). Evaluate Ghidra's own
   **Version Tracking** first — it may already be the matcher.
5. **Measure** — fact-survival rate (correct / wrong / orphaned), and characterize the hard
   failures (function splits, merges, inlining). → a **GO / ADJUST** number.

## Layout

| Path | What |
|------|------|
| `corpus/src/*.c` | small programs with real call-graph structure + named functions (ground truth) |
| `corpus/make_corpus.sh` | compiles the corpus: `{program} × {x86-64, aarch64} × {-O0, -O2}` |
| `corpus/bin/*.elf` | the generated corpus (committed so the spike's numbers are reproducible) |
| `harness/` | the analyzeHeadless wrapper + the snapshot dumper *(Sprint 1, in progress)* |

`mathlib` and **`mathlib_v2`** are the headline pair: v2 inserts an `lcm` function built on
`gcd`, shifting everything below it — exactly the structural change re-anchoring must survive.
The corpus keeps symbols (`-g`, unstripped) so we have ground-truth labels to score against;
real targets are stripped, so the matcher must *not* rely on symbols.

## Status

- [x] GayHydra headless available (`build/dist/ghidra_26.3.0_GayHydra-26.3.0/support/analyzeHeadless`)
- [x] Test-binary corpus generator + corpus
- [x] Model-snapshot dumper — `harness/dump_model.java` (Java GhidraScript; Ghidra 26.x dropped Jython for PyGhidra) + `harness/snapshot.sh`. Proven on the corpus: correct call edges, BB counts, mnemonic fingerprints.
- [x] Annotate / perturb / re-anchor / measure harness — `harness/reanchor.py` + `snapshots/`. See [REPORT.md](REPORT.md).
- [x] Matcher hardened — runtime-function exclusion + ordered-trigram signal + confidence threshold → **WRONG = 0 across every class** (failures degrade to flagged *orphans*, never silent clobber). **Verdict: GO** — same-opt re-analysis 100%; hard cases (O0→O2, cross-arch) fail safely and are an optimization, not a wall.
- [ ] Evaluate Ghidra Version Tracking head-to-head (lift hard-case *recovery*) + p-code signals for cross-arch *(Sprint 2 cont.)*
