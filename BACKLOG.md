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

- [ ] **Add a structural fingerprint to `scylla-model::Function`** (mnemonic histogram / hash, or
  bytes) and use it in `scylla-merge`'s signature. The model-only signature (bb-count / size /
  out-degree) is conservative and safe (`WRONG=0` holds) but **caps recovery**: the DD-038 gate
  shows the aarch64 edit class at 40% vs the prototype's ~100% with mnemonics. The prototype
  proved the signal exists; the production model just doesn't carry it yet. Landing the
  fingerprint raises the DD-038 ratcheted floors. **Never at the cost of `WRONG=0`.**

## Engine-as-service (DD-040)

- [ ] **Warm co-resident engine (perf).** Materialize cold-launches `analyzeHeadless` per call
  (~25s). Keep a GayHydra analysis context warm in-process instead. Gated on the
  classloader-coexistence spike (grpc-netty-shaded + GayHydra under one launcher); subprocess
  mode ships v1 behind the same RPC, so this is an optimization, not a redesign.
- [ ] **Wire the Rust core to the engine-port gRPC stream.** Today `scylla-ingest` reads the
  snapshot JSON via `materialize.sh`; the gRPC engine-service is a parallel path. Make the core
  consume the `Materialize` stream (resolve callee addrs → stable ids, mint via `IdMinter`) so
  the engine-port is *the* path, not a second one.
- [ ] **Config-ify the engine-service.** `GHIDRA_DIST` / `SCYLLA_SCRIPT_DIR` are
  hardcoded-with-env-default for the spike; and ship `dump_model.java` with the service instead
  of reaching into `prototype/harness`.

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
