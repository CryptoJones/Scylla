# Scylla — implementation map

The *why* lives in [DesignDecisions.md](DesignDecisions.md) (44 decisions). This is the *what*:
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
| `scylla-cli`    | the `scylla` CLI head — `materialize` (engine port) + `diff` / `merge` / `info` / `functions` / `search` / `view` / `callers` (offline, over the client port) | DD-009 / 040 / 017 |
| `scylla-merge`  | identity-anchored re-anchoring + collaboration merge + the **structural diff** (the binary-differ behind DD-017's `diff`) — `WRONG = 0` is the contract | DD-005 / 017 / 027 |
| `scylla-port`   | the client port — model-primary navigation, semantic zoom, annotation, **diff / merge**, typed errors | DD-017 / 019 / 020 / 021 |
| `scylla-mcp`    | the MCP head — projects the port 1:1 as agent tools; **no domain logic** | DD-022 / 024 / 025 |
| `scylla-wasm`   | the **browser head** — the client port compiled to wasm32; navigate/annotate/diff/merge a `.scylla` client-side (a pure port consumer) | DD-028 |
| `scylla-serve`  | the **native single-binary head** — a zero-dep binary that bakes in the WASM head and serves it + an artifact (auto-diffs two builds), no JVM | DD-028 |
| `scylla-rpc`    | the **remote head** — the client port over a Cap'n Proto promise-pipelining RPC `interface` (`scylla-rpc-serve` over TCP + the `scylla-rpc-connect` client: info/functions/view/callers/diff + rename/retype/comment + export; auth + cap + handshake + TLS) | DD-002 |
| `scylla-http`   | the **HTTP/JSON gateway head** — query *and annotate* the model over plain HTTP (info/functions/search/view/callers/diff + rename/retype/comment + export) from any language; token-gated, TLS-capable | DD-017 |
| `scylla-graphql`| the **GraphQL head** — the client port as one typed query graph (`query`: info/functions/search/function/callers/diff/export; `mutation`: rename/retype/comment), introspection + a GraphiQL console, one round-trip with no over/under-fetching; token-gated, TLS-capable | DD-017 |
| `scylla-tui`    | the **TUI head** — an interactive terminal navigator (ratatui) over the port: a function list, a selection-following detail pane (addr/blocks/size/callees/callers), and a live search filter; the `App` is a pure, conformance-tested port projection (lib+bin, testable headless) | DD-017 |
| `fuzz/`         | nightly cargo-fuzz harnesses for the three trust boundaries | DD-039 |

The consume-side core (`model` + `schema` + `port`) compiles to **wasm32** (DD-028) — that's the
`scylla-wasm` browser head, shipped by `scylla-serve`; the engine-touching producers deliberately do not.

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
6. **Diff** two builds → `scylla-port::Session::diff` (the structural binary-differ in `scylla-merge`):
   functions matched / renamed / **modified** / added / removed by structural identity,
   address-independent, climbing the BinDiff-style ladder EXACT → call-graph propagation → anchor
   (strings/imports) → BSim feature vector → fuzzy mnemonic + ordered-trigram cosine — the *same*
   matcher the merge uses, fail-closed (`WRONG=0`).

The client port is driven by **eight heads** today, each projecting the same verbs: `scylla-mcp`
(agents, JSON-RPC over stdio — all surfaced content untrusted, never instructions), `scylla-wasm`
(the browser, client-side), `scylla-serve` (the native binary serving it), `scylla-cli` (the
terminal), `scylla-rpc` (a remote consumer over Cap'n Proto promise-pipelining RPC, DD-002),
`scylla-http` (a plain HTTP/JSON gateway for any language), `scylla-graphql` (the same port as one
typed GraphQL graph), and `scylla-tui` (an interactive terminal navigator). Lop one off, grow
another; the body
never notices.

## Driving it

```
cargo test --workspace                         # everything, incl. the DD-038 re-anchoring gate (WRONG=0)
scripts/check-wasm.sh                           # DD-028: consume-side core compiles to wasm32
cargo +nightly fuzz run artifact_loader         # DD-039 nightly lane (per-commit replay rides in cargo test)
scylla materialize http://127.0.0.1:50051 <bin> out.scylla   # primary: binary -> .scylla over the engine port
prototype/harness/materialize.sh <bin> out.scylla            # offline alternative (no engine-service)
scylla diff [--json] a.scylla b.scylla          # structural diff (exit 1 if they differ); info/functions/view/callers too
scylla merge annotated.scylla rebuilt.scylla out.scylla      # carry annotations forward (DD-005)
cargo run -p scylla-serve -- a.scylla b.scylla  # serve the browser head; auto-diff two builds
node crates/scylla-wasm/web/verify.mjs          # headless check of the browser head
scylla-rpc-serve a.scylla 127.0.0.1:9000        # DD-002: serve the model over Cap'n Proto RPC
scylla-rpc-connect 127.0.0.1:9000 callers <id>  # the remote head: navigate over the wire (pipelined)
scylla-http a.scylla 127.0.0.1:8800             # the HTTP/JSON gateway: curl http://…/api/functions
curl -d '{"name":"euclid_gcd"}' http://…/api/functions/<id>/rename   # …and annotate it over HTTP
```

## Not built yet (on purpose)

The engine-as-service (DD-040) runs cold-start per request — it cold-launches `analyzeHeadless`
each call (~25s); a **warm co-resident engine** is the open perf work. Tier-1/2 corpus breadth
(DD-037) and a model structural fingerprint (to raise the DD-038 re-anchoring floors) are the
other open items. See [BACKLOG.md](BACKLOG.md).
