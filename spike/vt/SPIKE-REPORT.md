# Spike report — Ghidra Version Tracking (DD-042 de-risk)

**Verdict: NO-GO** for Version Tracking as the lever for Scylla's hard re-anchoring cases
(cross-architecture, full recompile). VT works headlessly and holds `WRONG = 0`, but on the cases
that actually matter it recovers **less** than the four-pass matcher Scylla already ships. The real
cross-arch lever is **BSim** (decompiler feature vectors) or a **Go-aware producer** — both separate,
heavier de-risks. This spike saved a multi-PR integration that would have underperformed.

## The question

After the anchor + propagation passes (DD-041), the functions Scylla still can't re-anchor are the
**symmetric arithmetic leaves** (no strings/imports, no distinguishing graph position) and
**cross-architecture** functions in general. Ghidra ships a whole Version Tracking subsystem built
for matching functions between program versions. Does driving it programmatically crack those cases?
De-risk before betting a multi-PR build (the warm-engine pattern).

## Does VT run headlessly? Yes (`ScyllaVtSpike.java`)

A standalone program imports + analyzes two binaries in-process (like the warm worker), builds a
`VTSessionDB`, runs correlators, and reads back the function matches. Two gotchas, both solved:

- **`ReadOnlyException: VT Session destination program is read-only`** — VT's constructor guards
  against a non-savable destination (a GUI safety check). Headless, the destination is a transient
  no-project program; pass `-DSystemUtilities.isTesting=true` to bypass the guard (VT writes to the
  *session*, never to the destination program, so this is safe here).
- **The reference correlator needs ACCEPTED seeds** — `CombinedFunctionAndDataReference` propagates
  only from associations marked `ACCEPTED` (the GUI workflow). Automate it: run the exact correlators,
  `setAccepted()` their matches, then run the reference correlator.

We deliberately did NOT use the **Symbol Name** correlator — it would trivially match by name on our
unstripped corpus and tell us nothing about stripped-binary reality. Only the **structural**
correlators (exact instructions / mnemonics, then seeded reference) were measured.

## Measured (mathlib, `WRONG = 0` throughout)

| case | VT exact (user funcs) | VT seeded reference | **Scylla four-pass** |
|------|----------------------|---------------------|----------------------|
| edit (O0→v2 O0) | gcd, fib, factorial, sum_to | + main | **100%** (exact) |
| recompile (O0→O2) | **0** (only CRT funcs match) | 0 user funcs | **40%** (main + fib) |
| cross-arch (x86-64→aarch64) | **0** | **0** | **40%** (main + fib) |

## Why NO-GO

VT's correlators are **exact instruction / byte / mnemonic** matchers. They shine at
**version-to-version patch diffing**: when 95% of functions are byte-identical, the exact correlators
seed that bulk and the reference correlator propagates to the few changed ones. That is the *opposite*
of Scylla's hard cases:

- **Recompile** changes every function's instructions → no user-function is byte-identical → exact
  correlators seed only the CRT runtime stubs → the reference correlator can't reach the user
  functions from those → **0 user functions recovered**. Scylla's mnemonic-cosine + recursion
  propagation gets 40%.
- **Cross-arch** shares no bytes, instructions, or mnemonics at all → every structural correlator
  returns **0** → no seeds → reference correlator returns 0. Scylla's *arch-independent* anchor
  (strings/imports) + recursion propagation gets 40%.

On the edit case VT matches Scylla (both get the byte-identical functions), so it adds nothing there
either. **VT is the wrong tool for the gap** — it would only help a use case (near-identical patch
diffing) Scylla doesn't currently target, and even then duplicates the exact pass.

## Recommendation

- **Do not integrate VT** for cross-arch / recompile re-anchoring. Keep the four-pass matcher.
- The genuine cross-arch lever is **BSim** (`VersionTrackingBSim` is in the dist) — LSH over
  *decompiler p-code feature vectors*, which abstracts away the ISA and is designed for
  cross-compiler / cross-architecture function similarity. It needs a feature-vector database, so
  it's a heavier, separate de-risk — the recommended next spike if cross-arch leaf recovery is worth
  pursuing.
- For Go specifically (`docs/corpus-findings.md`), a **Go-aware producer** (extract Go's string blob,
  devirtualize runtime calls) would let the existing anchor pass fire — likely cheaper than BSim.
- VT *would* be the right tool if Scylla ever targets **patch diffing of near-identical builds** (the
  classic CVE-patch use case); file it there, not here.

`ScyllaVtSpike.java` stays as the reproducible evidence + the headless-VT API reference (the
read-only bypass and the accept-then-propagate workflow are the non-obvious parts).
