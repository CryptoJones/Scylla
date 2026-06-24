# Dynamic-analysis EXECUTION HARNESS — staged build plan (PLAN, not built)

This is the engineering design for *building* the dynamic-analysis execution harness, staged so each
step is a shippable, independently-gated chunk — the same prototype-first discipline the rest of
Scylla was built with. It is the companion to [HARNESS-THREAT-MODEL.md](HARNESS-THREAT-MODEL.md):
the threat model says *what containment is required and which GAPs gate it*; this says *in what order
to build it and how each milestone proves itself*. **Nothing here is built.** Construction starts only
on an explicit go, **one milestone at a time**, each behind its gate. No hostile code runs before M5.

## Where we already are (M0 — done)

The cheap, no-regret groundwork is in and shipped, so the harness has somewhere to plug in:

- **The seam** (PR #92): a runtime artifact merges into the static model by `StableId`. GO.
- **Provenance** (PRs #94/#95, v0.5.0): facts *and* edges carry `Provenance { producer, confidence }`,
  so a dynamically-observed fact/edge is first-class and distinguishable.
- **Confidence-aware `collaborate`** (PR #98): the merge weighs provenance — a dynamic observation
  (high confidence it happened, partial coverage) can be reconciled against a static inference.
- **The interface + threat model** (PR #97): the `DynamicHarness` trait (with a non-executing
  `RecordedHarness`) and the containment threat model with the open GAPs (GAP-5..9).

So the producer-side contract, the model support, and the security bar all exist. What's missing is
the box that actually runs the sample — and that is pure security engineering.

## The milestones (each gated; do not proceed until the gate passes)

### M1 — the containment tier (no Scylla integration yet)
- **Build:** stand up a VM-grade sandbox that boots a minimal guest, runs a trivial *benign* program,
  and is destroyed — ephemeral, `--network none` at the hypervisor level (no NIC/route/DNS), no host
  FS, hard CPU/memory/wall-clock caps with a kill-switch. **Recommendation:** a Firecracker / Cloud
  Hypervisor microVM (KVM); gVisor is an acceptable lighter first cut but its syscall-emulation
  surface is itself attackable — microVM is the bar for hostile code. nsjail/containers are the
  DD-034 *parser* tier and are **not** sufficient here.
- **Gate (GAP-5, GAP-7):** a red-team pass — a deliberately escape-attempting + resource-bombing guest
  cannot reach the host, the network, or another run, and is reaped within budget. No further
  milestone until this holds. This is the hard, expensive milestone; everything after is plumbing.

### M2 — the one-way observation channel
- **Build:** a single bounded channel out of the guest (vsock / a serialized artifact on a read-back
  volume) carrying a *recorded trace*. The host treats it like a stranger's `.scylla`: DD-036-style
  caps (count/size limits), validate-then-quarantine, never `eval`.
- **Gate (GAP-6):** fuzz the channel with adversarial/oversized/malformed traces — the host parser
  never panics, OOMs, or trusts content; a hostile trace can at worst feed the matcher garbage that
  DD-007/DD-027 provenance-weighting must down-rank, never reach the host.

### M3 — the in-guest observer
- **Build:** what runs *inside* the VM to record observations. First target = the spike's proven win:
  a **resolved IAT** (rebuilt import table) + observed indirect-call edges for a packed/stripped
  sample. **Recommendation:** on Linux, a ptrace / Frida / QEMU-user-trace agent (per the eval, "a
  Linux dynamic producer is arguably a different tool wearing the same port" than Windows
  x64dbg/ScyllaHide — build the Linux one). Emits the trace M2 carries out.
- **Gate:** on a *benign* sample with a known IAT, the observer recovers it correctly (ground-truth
  comparison), reproducibly, within budget.

### M4 — the producer, end-to-end on benign samples
- **Build:** `MicroVmHarness: DynamicHarness` — wire M1+M2+M3 behind the trait the spike stubbed
  (`src/harness.rs`). `observe(sample)` runs the sample in the tier and returns `ObservedEdge`s; the
  core merges them via `collaborate`, stamping `Provenance { producer: "dynamic", confidence }` (the
  seam + DD-007 path, already built). Expose it behind the **engine port** as a second producer
  (opt-in, like `SCYLLA_ENGINE_WARM`), never the default.
- **Gate:** on the corpus's benign samples, the dynamic producer enriches the static model (the seam
  spike's measured uplift, now from a real run) with `WRONG = 0` preserved end-to-end.

### M5 — widen to hostile samples (the actual point)
- **Build:** only now, carefully, on an **isolated node**, opt-in, with the M1 red-team re-run against
  *real* malware behaviors (anti-analysis, network beaconing attempts, fork bombs, persistence).
- **Gate:** GAP-5..9 re-validated against hostile samples + an external pen-test. Evasion (GAP-8) is
  inherent — dynamic coverage is partial — so observations stay confidence-stamped and the analyst is
  told coverage was partial; never presented as ground truth.

## Integration points (all already exist)

- **Engine port** (DD-009/040): the harness is a *producer* behind the same port as the gRPC engine —
  a second source feeding the one model. No port change (the seam spike proved the projection).
- **DD-007 provenance**: observations stamp `producer: "dynamic"` + a confidence reflecting partial
  coverage. **DD-027 collaborate**: reconciles them against static facts by that confidence.
- **DD-036 loader caps**: the observation channel is an untrusted input; reuse the total-loader
  discipline.

## Effort & discipline

The cost is concentrated in **M1** (containment + its red-team) and **M5** (hostile-sample hardening +
external pen-test) — multi-week security engineering, not a feature. M2–M4 are comparatively
mechanical once M1 stands. The non-negotiables: **build one milestone at a time, behind its gate; no
hostile execution before M5; opt-in and isolated-node only; do not weaken DD-034.** The hexagon
guarantees the harness lands as an adapter with no body change — so deferring it costs nothing
structurally, and building it is a security project to be scheduled, not a loop iteration to slip in.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
