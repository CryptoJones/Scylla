# Spike report — BSim decompiler-signature similarity (DD-044 de-risk)

**Verdict: GO** for BSim as the cross-architecture lever for the **symmetric arithmetic leaves** the
four-pass matcher cannot re-anchor. BSim runs headlessly and **database-free** for the de-risk, and on
the exact cases that defeat every other signal it works: `factorial` and `sum_to` — leaves with no
strings, no imports, no callee-names, mnemonic-cosine 0, and nothing for propagation to lever from —
each match its cross-architecture twin at **similarity 1.000** (significance ~22, reciprocal-best),
and BSim keeps them apart despite being **one p-code opcode** different. `gcd` (the modulo leaf) does
NOT recover and correctly **flags fail-closed**. This is the lever the VT spike (DD-042) pointed at,
and it lands.

## The question

After the anchor + propagation passes (DD-041) and the Go-aware producer (DD-043), the functions
Scylla still can't re-anchor cross-architecture are the **symmetric arithmetic leaves**
(`gcd`/`factorial`/`sum_to`): pure arithmetic, so `string_refs`/`imports`/`callee_names` are all
empty; different ISA, so mnemonic cosine is 0; and being leaves, the call-graph propagation pass has
no anchored neighbour to lever from. BSim is the one tool aimed straight at this — LSH over the
**decompiler's p-code feature vectors**, an IR meant to abstract the ISA away. Does it actually fire
on these leaves, and does it hold `WRONG = 0`? De-risk before betting a multi-PR build (the
warm-engine / VT-spike pattern).

## Does BSim run headlessly, without a database? Yes (`ScyllaBsimSpike.java`)

BSim's *production* form wants a feature-vector database (H2/PostgreSQL) — but the de-risk question is
purely "do the cross-arch p-code vectors match," which needs no storage. The spike imports + analyzes
two binaries in-process (like the VT spike + the warm worker), then walks the **decompiler signature
path** Ghidra's own `CompareBSimSignaturesScript` uses:

- `WeightedLSHCosineVectorFactory` + the cross-arch weights from
  `GenSignatures.getWeightsFile(srcLang, dstLang)` — that call takes **both** language IDs precisely
  so a 64-bit-vs-64-bit pair resolves to the shared `lshweights_64` template.
- per function: `DecompInterface.setSignatureSettings(factory.getSettings())` →
  `generateSignatures(f, …)` → `factory.buildVector(sig.features)`.
- compare: `vecA.compare(vecB, vc)` (cosine 0..1) + `factory.calculateSignificance(vc)`.

No project, no server, no commit step — the whole de-risk is one `javac` against the dist jars. Ground
truth is the symbol name on the unstripped corpus; names are **never** a matching signal (same
discipline as the VT spike).

## Measured — `mathlib` x86-64 → aarch64, `-O0` (`WRONG = 0` under the gate)

Cross-architecture cosine-similarity matrix (rows = source x86-64, cols = dest aarch64; `*` = true
twin):

```
src\dst        main      gcd      fib  factorial   sum_to
main          1.000*   0.000    0.066    0.000     0.000
gcd           0.000    0.120*   0.000    0.310     0.310
fib           0.066    0.000    1.000*   0.000     0.000
factorial     0.000    0.111    0.000    1.000*    0.711
sum_to        0.000    0.111    0.000    0.711     1.000*
```

| source | best dest | sim | significance | reciprocal | gated outcome |
|--------|-----------|-----|--------------|------------|---------------|
| main | main | 1.000 | 42.73 | yes | **matched** |
| fib | fib | 1.000 | 27.90 | yes | **matched** |
| factorial | factorial | 1.000 | 21.94 | yes | **matched** |
| sum_to | sum_to | 1.000 | 21.94 | yes | **matched** |
| gcd | factorial | 0.310 | 8.16 | no | **FLAGGED (fail-closed)** |

- **Symmetric-leaf test:** `factorial→factorial = 1.000` vs `factorial→sum_to = 0.711` — **margin
  0.289**. The pair differs only in `INT_MULT` vs `INT_ADD`; that one opcode is enough for BSim to keep
  them distinct while still matching each to its own cross-arch self.
- **Naive argmax (no gate): 1 WRONG** (`gcd → factorial`, sim 0.310). **Gated (sim ≥ 0.70 +
  reciprocal-best): 4 matched, 0 WRONG, 1 flagged.**

## Why GO

BSim's premise holds for these leaves: the decompiler lifts x86-64 and aarch64 to **the same p-code
feature vector** for `main`, `fib`, `factorial`, and `sum_to` (cosine 1.000 across the ISA boundary,
where mnemonic cosine is 0). Crucially it cracks the two the matcher flags — `factorial` and `sum_to`,
the accumulator leaves — and does so without confusing them for each other. Projected onto the
cross-arch class, this lifts `mathlib` recovery from the matcher's **40%** (main + fib) to **80%**
(main + fib + factorial + sum_to); `gcd` stays flagged.

The one miss is instructive, not a defect. `gcd`'s Euclidean modulo (`a % b`) decompiles to materially
different p-code per ISA — x86-64 has a `DIV` that yields the remainder directly, aarch64 has no
modulo and synthesises it (`SDIV` + `MSUB`) — so its cross-arch self-similarity is only **0.120**,
*below* its 0.310 resemblance to the accumulator leaves. BSim genuinely cannot see through that
lowering. Under the gate it produces **no match** (sub-threshold, non-reciprocal, significance 8.16),
so `gcd` stays flagged — `WRONG = 0` preserved by failing closed, exactly as Scylla demands.

## The non-negotiable integration constraint

BSim must be gated on its **similarity floor (≥ 0.7) + reciprocal-best-match + significance** — never
raw argmax. Raw argmax emits the spurious `gcd → factorial` pick (the lone NAIVE WRONG above). This is
not a new mechanism: it is exactly Scylla's existing pass-3 **reciprocal-best** rule plus the
"beat the generic-neighbour baseline by a margin" discipline. Note `factorial → sum_to = 0.711` sits
just above a 0.7 floor — threshold alone is not enough; **reciprocal-best is load-bearing** (each true
twin scores 1.000, so the mutual-best resolves the pair cleanly).

## Recommendation

- **Integrate BSim as a cross-architecture re-anchoring pass** for the symmetric leaves — the gap no
  other signal touches. It is the genuine lever DD-042 named; this spike confirms it lands where VT
  did not.
- **Generation can stay database-free** along the `DecompInterface.generateSignatures` path the spike
  uses (one LSH vector per function, compared in-process) — a full BSim DB is only warranted once the
  corpus is large enough to need indexed nearest-neighbour search. For Scylla's per-pair re-anchoring,
  the direct vector compare is the right shape.
- **Gate hard:** sim ≥ 0.7 **and** reciprocal-best **and** a significance floor; wire it behind the
  existing pass-3 reciprocal-best machinery. Never argmax.
- **`gcd`-class leaves (division/modulo idioms) remain out of reach** of every current signal,
  including BSim — they stay flagged (fail-closed). That is honest coverage, not a regression; record
  it, don't paper over it.
- **Next:** widen the corpus measurement (more leaves, O0→O2 cross-arch, the C++ Tier-1 set) before
  ratcheting any gate floor, and confirm the `WeightedLSHCosineVectorFactory` weights behave the same
  on a 64↔32 pair (`lshweights_64_32`).

`ScyllaBsimSpike.java` + `run-spike.sh` stay as the reproducible evidence and the headless,
database-free BSim-signature API reference (the factory/weights setup and the decompiler signature
path are the non-obvious parts). `./spike/bsim/run-spike.sh` reproduces the table above in ~8s.
