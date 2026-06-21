# Scylla — implementation map

The *why* lives in [DesignDecisions.md](DesignDecisions.md) (39 decisions). This is the *what*:
the crates, how they connect, and how to drive them. If you want to change the structure, the
matching DD is the contract — read it before you argue with the shape.

## The two narrow waists

Producers feed a durable model; consumers read it; everything is pluggable on both sides.

```
 binary ─▶ [engine producer] ─▶ ⟡ engine-port ─▶ ┌──────────────┐ ─▶ ⟡ client-port ─▶ [heads]
                                                  │  THE MODEL   │
           [.scylla artifact] ◀─ ⟡ storage-port ─│  (Rust core) │
                                                  └──────────────┘
```

## Crates

Dependency direction is **heads → core, never the reverse** (DD-025/P6 — enforced by an
arch test in `scylla-mcp`).

| crate | what it is | realizes |
|-------|-----------|----------|
| `scylla-model`  | the domain model — stable synthetic ids, rich types, first-class durable user facts, the identity seam | DD-001 / 004 / 005 / 035 |
| `scylla-schema` | the canonical Cap'n Proto artifact + the **total loader** (explicit caps, validate, quarantine) | DD-002 / 026 / 036 |
| `scylla-engine` | the **engine port** (gRPC client to the sandboxed JVM engine-as-service) — the primary producer | DD-009 / 040 |
| `scylla-ingest` | the offline producer — a GayHydra headless snapshot JSON → model (dev / corpus, no running service) | DD-009 |
| `scylla-cli`    | the `scylla` CLI — `materialize` a binary into the artifact over the engine port (composition root) | DD-009 / 040 |
| `scylla-merge`  | identity-anchored re-anchoring + collaboration merge — `WRONG = 0` is the contract | DD-005 / 027 |
| `scylla-port`   | the client port — model-primary navigation, semantic zoom, annotation, typed errors | DD-017 / 019 / 020 / 021 |
| `scylla-mcp`    | the MCP head — projects the port 1:1 as agent tools; **no domain logic** | DD-022 / 024 / 025 |
| `fuzz/`         | nightly cargo-fuzz harnesses for the three trust boundaries | DD-039 |

The consume-side core (`model` + `schema` + `port`) compiles to **wasm32** (DD-028); the
engine-touching producers deliberately do not.

## Data flow

1. **Materialize** a binary into a `.scylla` artifact. Primary path — the engine port:
   `scylla materialize <endpoint> <binary>` → the sandboxed engine-service (DD-034) runs GayHydra
   over gRPC → the `Materialize` stream is assembled core-side into the model (id mint + callee
   resolution in `scylla_engine::assemble`). Offline alternative (no service):
   `prototype/harness/materialize.sh <binary>` → GayHydra headless → snapshot JSON → `scylla-ingest`.
2. `scylla-port::Session::from_artifact` loads it through `scylla-schema::load` — the **total
   loader** (never panics, never OOMs; soft faults quarantined, structural corruption rejected).
3. An agent drives `scylla-mcp` (newline-delimited JSON-RPC over stdio) → the client port →
   the model. All surfaced content is untrusted data, never instructions.
4. Re-import a changed binary → `scylla-merge` re-anchors prior user facts: high-confidence →
   carry it across; ambiguous/absent → flag it. **Never silently wrong.**
5. Share an artifact → `scylla-merge::collaborate` merges another analyst's facts (git-for-RE);
   disagreements surface as conflicts, never silent overwrites.

## Driving it

```
cargo test --workspace                         # everything, incl. the DD-038 re-anchoring gate (WRONG=0)
scripts/check-wasm.sh                          # DD-028: consume-side core compiles to wasm32
cargo +nightly fuzz run artifact_loader        # DD-039 nightly lane (per-commit replay rides in cargo test)
scylla materialize http://127.0.0.1:50051 <bin> out.scylla   # primary: binary -> .scylla over the engine port
prototype/harness/materialize.sh <bin> out.scylla            # offline alternative (no engine-service)
```

## Not built yet (on purpose)

The engine-as-service (DD-040) runs cold-start per request — it cold-launches `analyzeHeadless`
each call (~25s); a **warm co-resident engine** is the open perf work. Tier-1/2 corpus breadth
(DD-037) and a model structural fingerprint (to raise the DD-038 re-anchoring floors) are the
other open items. See [BACKLOG.md](BACKLOG.md).
