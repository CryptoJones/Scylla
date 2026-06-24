# Dynamic-analysis EXECUTION HARNESS — threat model & containment design (de-risk, NOT built)

**Verdict: the design is sound; building it stays GATED.** This document is the "own threat model"
the [eval](../../docs/eval-dynamic-analysis-producer.md) said the execution harness must have before
anyone writes it. It de-risks the *hard* half of a dynamic producer — safely **executing** a hostile
sample — at the design level. **No code here executes anything** (see `src/harness.rs`: the prototype
is a non-executing stub). Nothing in this spike weakens the DD-034 parser sandbox, and nothing should
until every GAP below is closed by a real containment tier.

The [seam spike](SPIKE-REPORT.md) already proved the *other* half: a runtime artifact merges into the
static model by identity (GO). What remained un-de-risked was the part that makes a human nervous —
running the malware. This is that.

## Why this is a new, harder trust tier (not an extension of DD-034)

The shipped [threat model](../../THREAT-MODEL.md) treats the binary as an **adversarial input that is
parsed** — S1 (the engine reads it), S3 (the artifact loader). The engine sandbox (DD-034) contains a
parser: it reads attacker-controlled bytes and must not be subverted by them. Crucially, **the sample
never runs.**

A dynamic producer changes the verb from *parse* to **execute**. The sample's own instructions run on
a CPU. Every assumption the parser sandbox makes ("the adversary controls data, not control flow") is
inverted: now the adversary controls control flow *by design*. This is **categorically** harder:

| | DD-034 parser sandbox (S1) | Execution harness (S6, this doc) |
|---|---|---|
| Adversary controls | input bytes | **the running program** |
| Threat | parser bug → RCE in the engine | the sample IS code, running on purpose |
| Containment goal | the parser can't be subverted | the sample can't escape / phone home / persist |
| Sufficient tier | process sandbox + caps + no-egress + timeout | **VM-grade isolation**, ephemeral, no-egress, observed-not-trusted |

So the harness does **not** reuse the DD-034 sandbox. It needs its own, stronger tier. Conflating the
two is the failure mode this document exists to prevent.

## S6 — sample → execution harness (the new seam)

```
hostile sample ─► [ EXECUTION HARNESS: VM-grade, ephemeral, no-egress sandbox ]
                        │  runs the sample, records observations
                        ▼
                  runtime artifact (resolved IAT, observed edges, coverage)
                        │  bounded + validated, UNTRUSTED by default (DD-036-style)
                        ▼
                  scylla-merge collaborate ─► model (edges/facts stamped producer="dynamic", DD-007)
```

The observations are **just another untrusted producer output** — they cross the same kind of boundary
S2 (engine→core) already defends, and they merge through the DD-007 provenance seam the prior PRs
built. The genuinely new thing is the box on the first line.

## Assets & the containment requirements

Assets at risk the moment the sample runs: **the host** (the analyst's machine / the service node),
**other samples** (cross-run contamination), **the network** (the sample phoning home, scanning, or
being used as a pivot), and **the model's integrity** (a sample that detects analysis and feeds false
observations). The containment tier must therefore provide, all of them load-bearing:

1. **VM-grade isolation, not a process sandbox.** A microVM (Firecracker / Cloud Hypervisor) or at
   minimum a gVisor-style syscall-interposing runtime. A namespace+seccomp container is the DD-034
   tier and is **not** sufficient for executing hostile code — kernel attack surface is too wide.
2. **Ephemeral & disposable.** Fresh VM per sample, destroyed after; no persistence, no shared writable
   state. Defeats cross-run contamination and most persistence techniques.
3. **No egress, hard.** `--network none` is necessary but not sufficient at this tier — no NIC, no
   routes, no shared sockets, no DNS. The sample cannot phone home, scan, or pivot. (The seam spike's
   IAT needs no network; richer dynamic analysis that *wants* controlled network gets a recorded/faked
   network, never the real one.)
4. **No host filesystem, no host devices.** The sample sees only its own ephemeral rootfs.
5. **Hard resource + wall-clock bounds.** CPU, memory, run-time, and a kill-switch — a sample that
   spins, forks, or balloons is reaped (the S1 GAP-2 timeout, raised to VM-lifecycle level).
6. **The observation channel is one-way and untrusted.** Observations leave the VM over a single
   bounded channel (a vsock/serialized trace), and the core treats them exactly like a `.scylla` from
   a stranger: cap counts/sizes, validate-then-quarantine (DD-036), never `eval`. A sample that detects
   the harness and emits adversarial "observations" can at worst feed the matcher garbage that
   `WRONG=0` + provenance-weighted `collaborate` (DD-027) must reject — it cannot reach the host.

## GAPs this introduces — all OPEN (execution is not built)

| Gap | Where | Risk | Status |
|---|---|---|---|
| GAP-5 | S6 | **Sandbox escape** — VM/hypervisor breakout to the host | **OPEN — gates the build** |
| GAP-6 | S6→core | **Observation-channel injection** — adversarial trace subverts the merge/parser | **OPEN** (mitigation: DD-036 caps + DD-007/DD-027 provenance weighting) |
| GAP-7 | S6 | **Resource exhaustion / fork-bomb** before the kill-switch | **OPEN** (mitigation: VM cgroup caps + wall-clock) |
| GAP-8 | S6 | **Evasion** — sample detects the harness, behaves benignly or lies | **OPEN, inherent** (dynamic analysis is coverage-partial by nature; provenance/confidence must record this) |
| GAP-9 | S6 | **Cross-run contamination / persistence** | **Mitigated by design** (ephemeral per-sample VM) but must be verified |

Unlike the shipped THREAT-MODEL's GAP-1..4 (all CLOSED), **these are open by construction**: closing
them is the work of *building* the harness, and that work is exactly what stays deferred until it's
prioritized with its own implementation + a real penetration pass.

## The staged build plan (what "later" concretely means)

1. **Done — the seam** (the [spike](SPIKE-REPORT.md)): a runtime artifact merges into the model. GO.
2. **Done — provenance** (DD-007, PRs #94/#95): facts + edges record `producer` + `confidence`, so a
   dynamically-observed edge is first-class and distinguishable.
3. **This doc — the containment design**: the tier + the S6 seam + the open GAPs. DESIGN only.
4. **Prototype, non-executing** (`src/harness.rs`): the `DynamicHarness` trait + a `RecordedHarness`
   stub that replays a recorded trace — proving the *interface* and the producer→model→provenance flow
   with **zero execution**. This is where a real `MicroVmHarness` would later plug in, behind GAP-5..9.
5. **Deferred — coverage-aware `collaborate`** (DD-027): weigh partial-coverage dynamic observations
   against full-coverage static inferences. Needed before dynamic data is trusted in the matcher.
6. **Deferred — the real harness**: only after a containment tier (microVM) is stood up *and*
   pen-tested against GAP-5..9, behind an explicit opt-in, on an isolated node. Not before.

## Closing

The hexagon guarantees the dynamic producer lands as an adapter behind the engine port — the seam is
proven and the provenance is in place. The only thing standing between here and a dynamic producer is
the containment tier, and that is a security-engineering project with its own pen-test, not a feature
to bolt on. We designed it before building it precisely so the design, not an incident, sets the bar.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
