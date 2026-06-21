# Scylla — Backlog

Tracked "later / someday" items that aren't on the current sprint path
([SprintPlanning.md](SprintPlanning.md)) but shouldn't be lost.

## Docs

- [ ] **Revisit the proposed architecture diagram** (`docs/proposed-scylla-architecture.drawio`).
  It's readable and hexagonal now, but the layout could be tightened — port placement on the
  rim, edge routing, balance of the driving/driven sides. A polish pass, not a redo.

## Possible future adapters (the whole point of the hexagon)

- [ ] **Evaluate the x64dbg / Scylla dynamic-analysis ecosystem as a future *producer* adapter**
  behind the engine port (DD-009/018). Found via x64dbg/**ScyllaHide** (an anti-anti-debug
  plugin — runtime, tangential to our static model) — but the relevant neighbors are the
  *dynamic* tools: **Scylla** (import reconstruction), debugger dumps, unpacked-at-runtime
  images. These don't replace the GayHydra static engine; they're a *second producer* that
  could feed runtime-resolved facts (real imports, dumped code, resolved indirect calls) into
  the **same model artifact** through the engine/binary-source ports. The narrow-waist design
  is exactly what makes "add a dynamic-analysis producer someday" a new adapter, not a rewrite.
  (Bonus: the name collision is on-brand — the RE scene loves "Scylla".)

## Re-anchoring recovery

- [x] **Add a structural fingerprint to `scylla-model::Function`.** `Function.fingerprint` is the
  FNV-1a hash of the mnemonic histogram (computed in `scylla-ingest` from the snapshot's
  `mnemonics`), folded into `scylla-merge`'s signature. It disambiguates coarse-signature
  collisions, lifting the **DD-038 aarch64 edit floor 40% → 80%** with `WRONG=0` held by
  construction (a richer signature only adds *unique* matches; a fingerprint collision is
  ambiguous → flagged, never wrong). Two follow-ups it opens:
  - [x] **Carry the mnemonic histogram over the engine.proto wire.** `FunctionChunk.mnemonics @6`
    carries the instruction stream raw; `EngineServer` populates it from `dump_model.java`, and
    `chunk_to_function` hashes it with the SAME `scylla_model::mnemonic_fingerprint` the snapshot
    path uses. Verified live: a gRPC-materialized mathlib artifact has 13/13 non-zero fingerprints
    that MATCH the snapshot path's exactly (0 mismatch) — the two producers re-anchor against each
    other. The engine never hashes; one hash, one place.
  - [ ] **Fuzzy / cross-build recovery for the hard classes.** Exact-fingerprint matching can't
    cross an optimization or architecture boundary (recompile/cross-arch dropped to 0% honest
    exact-match). The prototype's cosine + ordered-trigram + confidence-threshold matcher
    recovered those; bring it to production behind a confidence gate (still `WRONG=0`), or wire
    Ghidra Version Tracking. Needs the raw mnemonic histogram stored on the model, not just the
    hash.

## Engine-as-service (DD-040)

- [ ] **Warm co-resident engine (perf).** Materialize cold-launches `analyzeHeadless` per call
  (~25s). Keep a GayHydra analysis context warm in-process instead. Gated on the
  classloader-coexistence spike (grpc-netty-shaded + GayHydra under one launcher); subprocess
  mode ships v1 behind the same RPC, so this is an optimization, not a redesign.
- [x] **Wire the Rust core to the engine-port gRPC stream.** The new `scylla` CLI
  (`crates/scylla-cli`) is the composition root: `scylla materialize <endpoint> <binary>
  <out.scylla>` drives the engine-service over gRPC and consumes the `Materialize` stream straight
  into the canonical artifact — id mint + callee-address resolution happen core-side in
  `scylla_engine::assemble`. No intermediate snapshot file, no `materialize.sh` in the loop. Proven
  end to end: binary → gRPC → `.scylla` (13 mathlib functions, 952 bytes), then loaded back through
  the MCP head. The offline snapshot path (`scylla-ingest` + `materialize.sh`) stays for dev /
  corpus work without a running service. The composition lives in a CLI crate so neither the port
  adapter nor the WASM consume-side core carries the other's dependencies (DD-002).
- [x] **Config-ify the engine-service.** `dump_model.java` now lives in `engine-service/scripts/`
  (single source of truth) and ships in the install/image; `EngineServer` resolves it relative to
  its own jar, so the service no longer reaches into `prototype/harness` at run time and the
  sandbox runner drops the script mount. `GHIDRA_DIST` is now a REQUIRED, fail-fast config (no
  laptop-specific default), validated at startup; `SCYLLA_SCRIPT_DIR` defaults to the shipped
  scripts dir and is override-only.

## Security

- [ ] **Full no-egress lockdown for the engine sandbox (DD-034).** The container ships with a
  read-only rootfs, all caps dropped, no-new-privileges, non-root, mem/CPU/PID caps, and a
  size-capped RAM tmpfs — but gRPC is still published on host-loopback, so the parser *can*
  reach the network if something inside it tries. The strongest form is `--network none` + gRPC
  over a **bind-mounted unix socket**, so a hostile binary literally cannot phone home. That
  needs UDS transport in both the JVM service and the tonic client. Until then the sandbox
  contains blast radius (no host FS, no privilege, no core access) but not egress.
- [ ] **Threat-model the seams before Sprint 9 / before exposing the MCP head to untrusted input.**
  Decisions are locked (DD-014 sandbox the engine producer; DD-029 inherit GayHydra's
  deserialization posture + cosign), but a focused pass on (a) the engine producer that parses
  adversarial binaries and (b) the MCP head's input surface is worth doing deliberately rather
  than only at release time.
