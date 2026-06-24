# Dynamic-analysis harness — STATUS (one map over the whole build)

A single index over the harness work, which now spans many PRs and report files. The harness is built
as an **out-of-tree spike** (`spike/dynamic-analysis/`) so the shipped Scylla core is untouched until it
is ready; it lands as an adapter behind the engine port with **no body change** (the hexagon). **The
entire no-malware track is built and gated-green on ronin28; only real malware (M5.3/M5.4) remains, and
that is an infrastructure wall, not code.**

## Built + proven (no malware; on this box)

| Step | What it proves | Gate | Report |
|---|---|---|---|
| **M0 seam** | a runtime artifact merges into the model by `StableId` | GO | `SPIKE-REPORT.md` |
| **M0 provenance** | facts + edges carry `Provenance{producer,confidence}` (DD-007) | shipped v0.5.0 | — |
| **M0 threat model** | the S6 seam + GAP-5..9 + `DynamicHarness` trait | design | `HARNESS-THREAT-MODEL.md` |
| **M1** tier | ephemeral, no-egress, capped KVM microVM runs a benign guest | — | `harness-m1/M1-REPORT.md` |
| **M1 GATE** red team | a *hostile* synthetic guest can't escape/exhaust the host (16/16) | **PASS** | `harness-m1/M1-REDTEAM-REPORT.md` |
| **M2** channel | one-way serial trace out; bounded validate-then-quarantine reader | **GAP-6 fuzz PASS** (19) | `harness-m2/M2-REPORT.md` |
| **M3** observer | resolved IAT via the loader's `LD_DEBUG` (cooperative) | benign PASS | `harness-m3/M3-REPORT.md` |
| **M4** producer | `MicroVmHarness` end-to-end; observations stamped `producer="dynamic"` | `WRONG=0` | `harness-m4/M4-REPORT.md` |
| **M5.0** Firecracker | the tier migrated to Firecracker (smaller surface) + re-red-teamed | **PASS** | `harness-m5/M5_0-REPORT.md` |
| **M5.1** observer | uncooperative observer (`ltrace`/ptrace, no `LD_DEBUG`) in the tier | benign PASS | `harness-m5/M5_1-REPORT.md` |
| **M5.1 finding** | packing defeats PLT interception; syscall tracing survives | — | `harness-m5/M5_1-PACKED-FINDING.md` |
| **M5.2** uplift | a real run's edges merge into the model by identity | `WRONG=0` | `harness-m5/M5_2-REPORT.md` |
| **M5.2 persist** | the dynamic provenance (`@13`) survives the Cap'n Proto round-trip (durable) | `WRONG=0` | `harness-m5/M5_2-PERSIST-REPORT.md` |
| **M5.3 prep** | packing-resistant **syscall observer** runs in the Firecracker tier | benign PASS | `harness-m5/M5_3-SYSCALL-REPORT.md` |

### The two observers (both proven in the Firecracker tier)

- **Named-IAT** (M3 `LD_DEBUG` / M5.1 `ltrace`): recovers the resolved import table — for cooperative,
  unpacked samples. Defeated by packing.
- **Behavioral/syscall** (M5.3-prep `strace`/ptrace): recovers syscall behavior — **packing- and
  obfuscation-resistant**. The load-bearing one for real (packed) malware.

The producer picks the observation that fits; both feed the model as **partial-coverage
`producer="dynamic"`** data — confidence-stamped (DD-007), down-rankable by `collaborate` (DD-027),
**never ground truth**, and the matcher's `WRONG=0` re-anchoring gate is **never touched**.

## NOT done — the infrastructure wall (operator-provisioned)

**M5.3 (real malware) / M5.4 (external pen-test)** — see `HARNESS-M5-PLAN.md`. Needs, and **only
CryptoJones can provide**:

- [ ] an **isolated node** (not ronin28, a working laptop);
- [ ] the Firecracker **`jailer`** + a **minimal hardened guest kernel** (not the host's);
- [ ] a **malware corpus** (sourced, hashed, access-controlled);
- [ ] an **external pen-test** re-validating GAP-5..9 against hostile samples;
- [ ] **anti-trace hardening** of the syscall observer (GAP-8 evasion is inherent — recorded in
      provenance, never hidden).

Under CryptoJones's standing pre-authorization this is a **technical-readiness** gate, not a permission
one: no real malware runs until that infrastructure exists.

## Deferred (real-core integration, when scheduled)

- **Engine-port opt-in producer (M4 completion in the *real* core):** expose `MicroVmHarness` behind
  the engine port (DD-009/040) as an opt-in second producer (like `SCYLLA_ENGINE_WARM`), so
  `scylla materialize` can optionally enrich with dynamic observations. The hexagon guarantees this
  lands as an adapter with no body change; deliberately kept in the spike until the harness is ready.

## GAP table (from the threat model, current)

GAP-5 escape → **M1+M5.0 PASS** (synthetic; residual real-malware/0-day → M5.4 pen-test) · GAP-6 channel
injection → **M2 PASS** · GAP-7 exhaustion → **M1+M5.0 PASS** · GAP-8 evasion → **OPEN/inherent**
(provenance-recorded; syscall observer reduces packing-evasion) · GAP-9 persistence → **VERIFIED**.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
