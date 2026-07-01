# Changelog

All notable changes to Scylla are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The *why* behind every decision lives in [DesignDecisions.md](DesignDecisions.md) (44 DDs); the
*what* is mapped in [ARCHITECTURE.md](ARCHITECTURE.md). This file is the *when*.

## [0.7.0] — 2026-07-01

A security- and robustness-hardening pass across the whole platform — the fixes from a full code
review ([RECOMMENDATIONS.md](RECOMMENDATIONS.md)). No new heads and no artifact-format change, but the
breadth of the hardening (and a few fail-closed behavior changes — TLS half-config, the CLI
`materialize` exit code) makes this a SemVer minor.

### Security

- **`WRONG = 0` re-anchoring holes closed (scylla-merge).** The EXACT and ANCHOR passes and the
  `collaborate`/`propagate` paths now require BOTH-sided uniqueness and a reciprocal-best match (the
  discipline the diff path already used), so a deleted or twin function can no longer silently
  mis-attach an analyst's fact. Adversarial regression tests added.
- **The `<untrusted-data>` prompt-injection envelope is no longer escapable (scylla-mcp, scylla-lsp,
  DD-035).** A hostile binary whose name/comment embedded the closing sentinel could end the envelope
  early; both fence tokens are now neutralized before wrapping.
- **Network heads (scylla-http, scylla-graphql, scylla-rpc):** constant-time bearer-token comparison,
  TLS fails closed on a half-configured cert/key, request bodies are size-capped, and a per-request
  panic can no longer take the server down.
- **scylla-rpc no longer dies on a transient `accept()` error** (a remote, pre-auth availability
  kill), and the TLS handshake is time-bounded so it can't squat a connection slot; explicit inbound
  reader limits replace the library default.
- **The total loader (scylla-schema) truncates every untrusted string, drops dangling
  edge-provenance and duplicate ids, and loads zero-copy** so a tiny artifact can't declare a
  half-gigabyte segment.
- **Stable-id collisions on duplicate/unparseable addresses fixed** in the offline (scylla-ingest)
  and engine (scylla-engine) producers — identity is the minted id, never the address (DD-004).
- **engine-service (JVM):** the analysis deadline kills the whole Ghidra process tree (not just the
  launcher script), the gRPC inbound limit fits a real firmware, cold analyses are concurrency-capped,
  and the per-request temp project directory is cleaned up.

### Fixed

- MCP/LSP stdio input is size-capped and resilient to a stray non-UTF-8 byte; LSP `Content-Length` is
  bounded and ranges are measured in UTF-16 (so a rename covers the whole line).
- scylla-port surfaces the loader's `LoadReport`, and `functions`/`search` are O(N+E), not O(N²).
- scylla-cli `materialize` uses exit code 2 for trouble (1 stays reserved for "diff differs").
- scylla-wasm guards its wasm32-only pointer packing; scylla-tui restores the terminal on a panic;
  scylla-serve caps handler threads and rejects non-GET/HEAD.

### CI

- CI runs clippy (`-D warnings`), tests `--locked`, and builds the JVM engine-service on every change
  (not only at release).

## [0.6.0] — 2026-06-24

Provenance starts *doing work*: the merge now reconciles disagreement by it. With facts and edges
carrying `Provenance { producer, confidence }` since v0.5.0 (DD-007), `collaborate` — the git-for-RE
merge of two analysts' work — settles a conflict by whose fact is more trusted, instead of always
deferring it to a human. Confined to the collaboration path; the re-anchoring matcher and the
`WRONG = 0` gate are untouched (a SemVer minor, no head or artifact change).

### Changed

- **`collaborate` is now confidence-aware (DD-027).** When two analysts' facts disagree on the same
  entity, the merge settles it by `Provenance::confidence` (DD-007): a side that clearly wins (by more
  than a 5-point margin) takes over and is counted in the new `CollabReport.resolved_by_confidence`; a
  near-tie is still surfaced as a `Conflict`, never guessed — the same "unique winner clearing a
  margin" discipline the re-anchoring matcher holds for `WRONG = 0`. The matcher and the re-anchoring
  gate are untouched; this is the final productionization step on top of provenance.

## [0.5.0] — 2026-06-24

Provenance becomes first-class (DD-007): the durable model now records WHO produced each fact and
each call-graph edge, and how strongly — so a human rename, a static engine inference, and a future
dynamic observation are all distinguishable. Slotted in additively (the Cap'n Proto artifact's whole
point, DD-002); old `.scylla` files load unchanged. No head or matcher change (a SemVer minor).

### Added

- **Producer provenance on durable facts (DD-007).** Every `UserFact` now carries a
  `Provenance { producer, confidence }` — a free producer label (`"user"`, or an engine/producer
  name) plus a `0..=100` trust — so a human rename is distinguishable from an engine guess or a
  re-anchored carry-over. Slotted into the Cap'n Proto artifact **additively** (`model.capnp`
  `@4`/`@5` — the evolution DD-002 was built for): **old artifacts load unchanged**, defaulting to a
  certain `user` fact (back-compat tested by hand-building a pre-provenance fact). The port stamps
  analyst annotations `user`/100; re-anchoring (`retarget`) preserves provenance; a producer stamps
  its own via `UserFact::with_provenance`. The no-regret groundwork the dynamic-analysis seam spike
  (`spike/dynamic-analysis/`) validated.
- **Per-edge provenance (DD-007).** The call graph's edges carry provenance too now: `Function` gains
  a sparse `edge_provenance` sidecar (`EdgeProvenance { target, provenance }`, `model.capnp` `@13`)
  marking which `callees` a producer resolved with a recorded producer + confidence — e.g. an edge a
  dynamic producer observed at runtime that static analysis left dangling (the seam spike's other
  half). `callees` itself is untouched, so the matcher is unaffected; the sidecar is empty on every
  existing model (back-compat tested), and `Function::edge_provenance_of(target)` returns the stamp
  or `None` (an ordinary static call). Coverage-aware `collaborate` (DD-027) remains future.

## [0.4.0] — 2026-06-24

The ninth head — an LSP server, so an editor navigates the model with the go-to-symbol / hover /
find-references / rename it already has for source — plus a diff pane for the TUI, so a structural
diff is browsable in the terminal. Both are thin projections of the one client port (DD-017): no
body, no contract, no schema change (a SemVer minor). Eight heads became nine.

### Added

- **`scylla-tui` diff pane (DD-017).** Pass a second artifact (`scylla-tui a.scylla b.scylla`) and
  press `d` / Tab to toggle a structural-diff screen: a summary line (unchanged / renamed / modified
  / added / removed) over a color-coded, scrollable list of the changes, each carrying its recovery
  rung + confidence from the matcher's provenance. The diff is `Session::diff` folded into rows by
  the headless `App` (still zero terminal dependency), conformance-tested against the port.
- **`scylla-lsp` — the ninth head: a Language Server (DD-017).** Editors (nvim / VS Code) navigate a
  `.scylla` model like source. The program is projected as one virtual document (functions in address
  order): `documentSymbol` is the `functions` verb, `hover` is `view` at DETAIL (Markdown, wrapped
  `<untrusted-data>` per DD-035), `references` is the `callers` verb (the call graph read backwards),
  `rename` is the annotate verb returned as a `WorkspaceEdit`, and `workspace/symbol` is `search`.
  Hand-rolled `Content-Length` JSON-RPC like the MCP head; the `dispatch` router is a pure,
  headless-testable port projection (lib + bin), conformance-tested verb-for-verb — no editor.

## [0.3.0] — 2026-06-23

Two more heads grown on the v0.2.0 body, both thin projections of the one client port (DD-017) —
the hexagon's whole bet, paid out: grow a new head and the body never notices. No body, no
contract, no schema change (a SemVer minor). Six heads became eight.

### Added

- **`scylla-graphql` — the seventh head: a GraphQL gateway (DD-017).** The client port projected as
  one typed graph — `query` (info / functions / search / function / callers / diff / export) +
  `mutation` (rename / retype / comment) — so a client fetches exactly the function / caller / diff
  shape it wants in a single round-trip, with schema introspection and a GraphiQL console at
  `GET /graphql`. A thin projection of `scylla_port::Session` like every head (conformance-tested
  against the port, verb-for-verb); binary `.scylla` artifacts cross the JSON boundary base64-encoded
  (the `diff` input and the `export` output). Token-gated (`SCYLLA_GRAPHQL_TOKEN`) and TLS-capable
  (`SCYLLA_GRAPHQL_TLS_CERT` / `_KEY`), mirroring the HTTP head. Synchronous `juniper` execution on
  the same `tiny_http` server — no async runtime.
- **`scylla-tui` — the eighth head: an interactive TUI navigator (DD-017).** A `ratatui` terminal app
  over the model — a function list, a detail pane (address / basic blocks / size / callees / callers)
  that follows the selection, and a live `/` search filter. The `App` (model + UI state) is a pure
  projection of `scylla_port::Session` with zero terminal dependency, conformance-tested against the
  port verb-for-verb (no pty); the crossterm shell only turns keystrokes into `App` calls. Lib + bin
  so the navigation logic is testable headless.

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

[Unreleased]: https://codeberg.org/CryptoJones/Scylla/compare/v0.7.0...HEAD
[0.7.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.6.0...v0.7.0
[0.6.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.5.0...v0.6.0
[0.5.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.4.0...v0.5.0
[0.4.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.3.0...v0.4.0
[0.3.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.2.0...v0.3.0
[0.2.0]: https://codeberg.org/CryptoJones/Scylla/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/CryptoJones/Scylla/src/tag/v0.1.0
