# Changelog

All notable changes to Scylla are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The *why* behind every decision lives in [DesignDecisions.md](DesignDecisions.md) (44 DDs); the
*what* is mapped in [ARCHITECTURE.md](ARCHITECTURE.md). This file is the *when*.

## [Unreleased]

Nothing yet.

## [0.2.0] — 2026-06-23

The platform built out on the v0.1.0 core spine: from a model + MCP-head + merge foundation to a
**feature-complete, six-headed** RE platform with a real fail-closed binary-differ. A durable,
transport-agnostic RE **domain model** (the *body*) wrapped behind thin, disposable protocol
**adapters** (the *heads*) — the body is the one bet that can't be taken back; the heads are cheap on
purpose. Everything below is backward-compatible with v0.1.0 (a SemVer minor bump).

### The body (the durable core)

- **`scylla-model`** — the RE domain vocabulary: functions, the call graph, and **first-class
  durable user facts** (renames / retypes / comments) attached as edges onto **synthetic stable
  ids** (DD-001/004/005). Identity is the minted id, never the address — so a user's work survives
  when code moves. Carries the matcher's feature set per function: mnemonic histogram + **ordered
  trigrams**, FNV fingerprint, arch-independent string/import/callee-name anchors, and the BSim
  decompiler-signature vector.
- **`scylla-schema`** — the canonical **Cap'n Proto** model-artifact (DD-002/026) plus the **total
  loader** (DD-036): explicit reader caps, validate-then-quarantine, never panics, never OOMs. A
  structurally broken artifact is a typed error; soft faults are quarantined and counted.
- **`scylla-port`** — the **client port**: the one verb set every head projects —
  navigate / **search** / annotate / **diff** / **merge** / **export**, with semantic zoom (DD-020)
  and typed errors (DD-021). Compiles to `wasm32`.

### The six heads

Each projects the *same* client port; lop one off and grow another, the body never notices.

- **`scylla-mcp`** — the MCP head (DD-022/024/025): the port projected 1:1 as agent tools, no domain
  logic. All binary-derived content is wrapped in an explicit `<untrusted-data>` envelope (DD-035):
  an agent reads it as data, never instructions.
- **`scylla-wasm`** — the browser head (DD-028): the port compiled to `wasm32`, navigating /
  annotating / diffing / searching a `.scylla` artifact entirely client-side. Renders the call graph
  and paints a structural diff onto it; headless-verified.
- **`scylla-serve`** — the native single binary: a zero-dependency server that bakes in the browser
  head and serves it + an artifact, auto-diffing two builds. No JVM.
- **`scylla-cli`** — the `scylla` terminal head: `materialize` (engine port) +
  `diff` / `info` / `functions` / `search` / `view` / `callers` / `merge` offline. `scylla diff`
  carries `git diff --exit-code` semantics for CI.
- **`scylla-rpc`** — the remote head (DD-002): the client port over a Cap'n Proto
  **promise-pipelining** RPC interface — `session.function(id).callers().view()` is one round-trip.
  Capability-based auth, connection cap, slow-loris handshake bound, and TLS.
- **`scylla-http`** — the HTTP/JSON gateway (DD-017): query / annotate / diff / export the model over
  plain HTTP from any language. Token-gated and TLS-capable.

### The matcher (DD-005/017/027/038/041/043/044)

- A real binary-differ behind the `diff` verb, **at parity with the identity-anchored merge** — the
  same matcher carries annotations across a rebuild and reports a structural diff. Functions pair by
  address-independent structural identity, climbing a BinDiff-style ladder: **EXACT** signature →
  multi-round call-graph **propagation** → **anchor** (Jaccard over strings/imports/callee-names,
  the cross-architecture lever) → **BSim** decompiler-signature cosine → **fuzzy** (mnemonic +
  ordered-trigram cosine + structural closeness).
- Reports functions matched / renamed / **modified** / added / removed — a changed body is
  re-identified as *modified*, never reported as remove+add.
- **`WRONG = 0` is the contract**: every pass is fail-closed — a unique reciprocal winner clearing a
  threshold and a runner-up margin, never a guess between near-ties.
- **Match provenance**: every matched/changed pair records *how* it was recovered (the ladder rung)
  and *how strongly* (a confidence %), surfaced on every head.

### The producers

- **`scylla-engine`** — the engine port (DD-009/040): a gRPC client to the sandboxed JVM
  engine-as-service (GayHydra over `analyzeHeadless`), assembled core-side into the model. Bounds the
  untrusted stream; fails closed.
- **`scylla-ingest`** — the offline producer: a GayHydra headless snapshot → model, for dev / corpus
  work without a running engine-service.

### Security posture

- Untrusted binary-derived content delimited as data on the agent head (DD-035); the total loader on
  the artifact boundary (DD-036); the engine sandbox + bounded streams (DD-014/029/034); the remote
  head's auth + connection cap + slow-loris bound + TLS. Three trust boundaries fuzzed nightly
  (DD-039); a re-anchoring regression gate holds `WRONG = 0` per commit (DD-038).

### Verification

`cargo test --workspace` (incl. the re-anchoring gate and per-head contract-conformance),
`scripts/check-wasm.sh` (the consume-side core builds for `wasm32`), and
`node crates/scylla-wasm/web/verify.mjs` (the browser head round-trip) all green.

## [0.1.0] — 2026-06-21

The **durable core spine** — design-locked and prototype-de-risked, *not a production RE tool yet*.

### Added

- The body: the RE domain model (`scylla-model`), the Cap'n Proto model-artifact + round-trip
  (`scylla-schema`), GayHydra → `.scylla` materialization (`scylla-ingest`), the identity-anchored
  merge (`scylla-merge`), and the client port with semantic zoom (`scylla-port`) — six Rust crates.
- The **MCP head** (`scylla-mcp`): agents can drive an RE session over the port.
- Collaboration (git-for-RE artifact merge); the consume-side core builds to `wasm32`.
- The keystone risk — re-anchoring an analyst's facts across re-analysis — empirically de-risked:
  zero silent mis-attachment, made a code invariant (`WRONG = 0`).
- 33 design decisions locked with rationale; 20 tests, CI, CONTRIBUTING, SECURITY.

[Unreleased]: https://codeberg.org/CryptoJones/Scylla/compare/v0.2.0...HEAD
[0.2.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/CryptoJones/Scylla/src/tag/v0.1.0
