# Scylla — Sprint Planning

Companion to [DesignDecisions.md](DesignDecisions.md). Every sprint cites the DDs it realizes.

## The unit

A **sprint = ~8 hours of actual Claude Code work** — agent execution time, not human
calendar time. Each sprint has a concrete **Definition of Done (DoD)** you can check, and
names the **DDs** it turns from a decision on paper into running code.

## The one principle that orders everything: prototype-first

The whole platform rests on one unproven assumption — **DD-004's re-anchoring** (can a
user's renames/types/comments survive re-analysis when the binary's structure shifts?). If
that fails, DD-005, DD-027, and "never lose the analyst's work" all fail with it. So the plan
front-loads **only the minimum prerequisites the prototype needs**, runs the prototype, gets
a go/no-go number — *then* builds the durable architecture on proven ground.

Everything before the prototype is there *only* because the prototype can't run without it.

---

## Sprint 1 — Prototype prerequisites  ·  *the minimum to run the spike*  ·  ~6–8h

**Goal.** Stand up *just enough* to run the re-anchoring spike — none of the durable core.

**Prereqs.** None (a GayHydra checkout).

**Tasks.**
- Build + run **GayHydra headless** (`analyzeHeadless`) reproducibly — pin a build, script the invocation.
- A **model-snapshot harness**: analyze a binary → dump a normalized JSON snapshot (functions, entry points, basic blocks, call edges, symbols, a per-function p-code/instruction fingerprint, decompiled text).
- A **test-binary corpus**: compile a handful of small C programs at `-O0` and `-O2`, plus a "v2" with a deliberate source edit (insert/reorder a function), across ≥2 architectures → produces `(A, A@-O2, A-edited)` triples.

**DoD.** `harness.sh <binary>` emits a deterministic snapshot JSON; a corpus of ≥6 binary pairs exists and is documented.

**Realizes.** DD-011, DD-010, DD-013; seeds DD-001 (what a snapshot contains).

**Risk.** GayHydra headless build friction — bounded, known.

---

## Sprint 2 — ★ THE KEYSTONE PROTOTYPE  ·  *re-anchoring de-risk*  ·  ~8h

**Goal.** Answer the question the platform rests on, cheaply, before anything is built on it: **do user facts survive re-analysis across structural change?** Produce a number.

**Prereqs.** Sprint 1.

**Tasks.**
- **Annotate** — attach synthetic-ID-keyed user facts (rename, retype, comment) to model-v1 entities.
- **Perturb** — produce model-v2 from (a) re-analysis with different settings and (b) the recompiled/edited variant.
- **Re-anchor** — match v2 entities back to v1 IDs via binary-diff signals (call-graph position, CFG/p-code fingerprint, decompiled-text similarity). **Evaluate Ghidra's built-in Version Tracking first** (cheapest — may already be the matcher), then a custom matcher only if needed.
- **Measure** — fact-survival rate (correct / wrong / orphaned) per perturbation class; characterize the hard failures (function splits, merges, inlining).

**DoD.** A written report (`docs/prototype/`) with survival-rate numbers per perturbation class and a clear **GO** (DD-004/005 stand) or **ADJUST** (named fallback) recommendation.

**Validates.** DD-004, DD-005 — and by extension DD-027.

**Gate.** If survival is unacceptable and no matcher reaches it, revisit DD-004/005 *before* Sprint 5. This is the cheapest possible test of the most expensive assumption.

---

## Sprint 3 — Core scaffold  ·  *Rust workspace + model types + own format*  ·  ~8h

**Goal.** The durable core's skeleton: the model as Rust types + the Cap'n Proto artifact, round-trippable.

**Prereqs.** Sprint 2 (model shape confirmed).

**Tasks.**
- Cargo workspace (`core`, `schema`, `engine-port`, `heads` crates).
- Domain-model Rust types (DD-001): rich types, entities, **stable synthetic IDs** (DD-004) with minting + an ID registry.
- **Cap'n Proto schema v0** of the model (DD-002); serialize/deserialize the **model-artifact** (DD-026 own format); native-mutable-in-core ↔ Cap'n-Proto-on-disk (DD-002 resolution).
- Round-trip + golden tests (DD-030 seed); arch-test stub (DD-025).

**DoD.** Build a model in-core → persist to a Cap'n Proto artifact → reload → assert identity; CI green.

**Realizes.** DD-016, DD-001, DD-004, DD-002, DD-026, DD-015, DD-003 (p-code field).

---

## Sprint 4 — Engine port + materialization  ·  *end-to-end*  ·  ~8h (may split)

**Goal.** Drive GayHydra as a droppable producer and materialize a real binary into the model-artifact.

**Prereqs.** Sprint 1 (harness), Sprint 3 (model types).

**Tasks.**
- Define the **engine-port protocol** (DD-009/018): JVM-friendly (gRPC or a small framed protocol) — `materialize` · `analyze` · `decompile`.
- GayHydra-side **service** exposing it (Ghidra extension / headless service).
- Rust **engine-port client**; spin-up/teardown lifecycle — **droppable engine** (DD-009), **session lives in the core** (DD-006).
- Materialize: bytes → engine → model-artifact, persisted; engine dropped after.

**DoD.** `scylla import <binary>` produces a persisted model-artifact via the live engine (then dropped), over a multi-binary smoke set.

**Realizes.** DD-009, DD-010, DD-018, DD-012, DD-014 (sandbox seam), DD-006.

---

## Sprint 5 — The merge engine  ·  *productionize the prototype*  ·  ~8h

**Goal.** Turn the spike's re-anchoring into the core's real merge path.

**Prereqs.** Sprint 2 (findings), Sprint 4 (materialization).

**Tasks.**
- **Identity-anchored merge** (DD-005): re-analysis emits machine facts that merge against stable-ID-keyed user facts — user wins on conflict, non-conflicting machine updates flow through.
- Re-anchoring per the prototype's chosen matcher; conflict + orphan handling (surfaced, never silently dropped); provenance hooks (DD-007 deferred but schema-ready).
- The Sprint-1 corpus as merge regression fixtures (DD-030).

**DoD.** Re-import a perturbed binary; user facts survive at the prototype's measured rate; conflicts are surfaced.

**Realizes.** DD-005, DD-004; foundation for DD-027.

---

## Sprint 6 — Client port + semantic zoom  ·  ~8h (may split)

**Goal.** The consumer-facing waist — the navigable model + command set at the right altitude.

**Prereqs.** Sprint 3/4.

**Tasks.**
- **Client port** (DD-017): navigable graph + curated commands (`import` · `analyze` · `decompile` · `rename` · `retype` · `comment` · `diff`).
- **Semantic-zoom** altitude (DD-020): domain default, p-code down (escape hatch), intent composed by the consumer.
- Sync + **job-handle** for long `analyze` (DD-019); **typed error taxonomy** mirroring Ghidra (DD-021); Cap'n Proto RPC surface (DD-002) — **served in-process** (heads drive `scylla_port::Session` directly; the MCP head marshals JSON-RPC), with the Cap'n Proto **promise-pipelining RPC wire deferred** to a future remote/networked head (see BACKLOG; the model-artifact persistence half of DD-002 is done).

**DoD.** A non-MCP test client drives a full session (import → analyze → navigate → annotate → persist) over the port; zoom levels return the right detail.

**Realizes.** DD-017, DD-020, DD-019, DD-021, DD-002.

---

## Sprint 7 — The MCP head (v1)  ·  *the differentiator*  ·  ~8h

**Goal.** Agents reverse-engineer binaries via MCP.

**Prereqs.** Sprint 6.

**Tasks.**
- MCP server projecting the client port **1:1** as tools (DD-022/024); **no domain logic** (P6).
- **Arch-test** enforcing the core→heads boundary (DD-025).
- An agent script that plans + runs an RE session end-to-end.

**DoD.** An MCP client (Claude) imports a binary, analyzes, decompiles, renames — and the rename persists across a re-analysis; arch-test green.

**Realizes.** DD-022, DD-024, DD-025; DD-023 (roster noted, not built).

---

## Sprint 8 — Distribution + collaboration  ·  *spend the Rust payoff*  ·  ~8h

**Goal.** Cash in DD-016; enable git-for-RE.

**Prereqs.** Sprint 6/7.

**Tasks.**
- **Native single-binary** build of the serving core (**DONE: `crates/scylla-serve`** — a zero-dep binary that serves the embedded WASM head + an artifact, no JVM); **WASM** build for a browser consumer (DD-028) — **DONE: `crates/scylla-wasm`** (the port compiled to wasm32; a browser navigates/annotates/merges a `.scylla` artifact client-side, headless-verified; the demo renders the call graph as an actual directed graph + has live function search); engine fetched-separately packaging.
- Model-artifact **export/import** for collaboration sync — single-user v1 (DD-027).
- Decompile-result **caching** + structured logging (DD-031).

**DoD.** A single static binary serves a pre-built artifact with no JVM present; a WASM demo navigates an artifact in-browser; two checkouts exchange an artifact.

**Realizes.** DD-028, DD-027, DD-031.

---

## Sprint 9 — Hardening, security, governance, v0.1 release  ·  ~8h

**Goal.** Production posture + first signed release.

**Prereqs.** All prior.

**Tasks.**
- **Sandbox** the engine producer (DD-014/029); **cosign** releases; inherit GayHydra's deserialization posture.
- Golden-binary regression corpus expanded (DD-030); contract-conformance per head.
- **CONTRIBUTING** + issue/PR lanes + triage SLA (DD-033); license/NOTICE accuracy (DD-032).
- Confirm in code: SLEIGH/.sla wholesale (DD-013), decompiler boundary as-is (DD-012), P-code at the escape hatch (DD-003).

**DoD.** Signed **v0.1** with the corpus green; CONTRIBUTING live; security notes documented.

**Realizes.** DD-029, DD-014, DD-030, DD-032, DD-033, DD-013, DD-012, DD-003.

---

## Shape of the whole

**~9 sprints ≈ 72h of Claude Code work to a signed v0.1.** Sprints 1–2 (≈16h) are the only part
that *must* succeed before the rest is worth building — everything after assumes the prototype
said GO. If it says ADJUST, the fix lands before Sprint 5 and the downstream sprints absorb it.

```
S1 prereqs ─► S2 ★PROTOTYPE ─► S3 core ─► S4 engine-port ─► S5 merge ─┐
                                            └─► S6 client-port ─► S7 MCP ─► S8 dist/collab ─► S9 release
```

## DD coverage (every decision lands in a sprint)

| Sprint | DDs realized |
|--------|--------------|
| 1 | DD-010, DD-011, DD-013 (+ DD-001 seed) |
| 2 | DD-004, DD-005 (validate) |
| 3 | DD-016, DD-001, DD-004, DD-002, DD-026, DD-015, DD-003 |
| 4 | DD-009, DD-010, DD-018, DD-012, DD-014, DD-006 |
| 5 | DD-005, DD-004, DD-007 (hooks) |
| 6 | DD-017, DD-020, DD-019, DD-021, DD-002 |
| 7 | DD-022, DD-024, DD-025, DD-023 |
| 8 | DD-028, DD-027, DD-031 |
| 9 | DD-029, DD-014, DD-030, DD-032, DD-033, DD-013, DD-012, DD-003 |

All 33 DDs are covered; DD-008 (contract versioning) rides alongside DD-002 from Sprint 3 on.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
