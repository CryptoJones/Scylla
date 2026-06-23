# scylla-wasm — the WASM head (DD-028)

The client port (`scylla_port`) compiled to **WebAssembly**, so a browser navigates a `.scylla`
model-artifact **entirely client-side** — no server, no engine. It is a new head in the
hexagon's sense: the **first out-of-process consumer** of the port, projecting the same
navigate/zoom surface the in-process and MCP heads use.

```
.scylla artifact  ──►  WASM Session (scylla-port, in the browser)  ──►  navigate / zoom
   (DD-026)                 no server · no JVM engine · no round-trips
```

## Why raw wasm32 (no wasm-bindgen)

The head exposes a tiny **C ABI** the browser drives directly over linear memory — zero external
toolchain beyond the `wasm32-unknown-unknown` target. The module is self-contained (no imports).

| export | meaning |
|---|---|
| `scylla_alloc(len) -> ptr` | reserve `len` bytes; JS writes the artifact there |
| `scylla_load(ptr, len) -> 0/-1` | load the artifact into the session (validating loader, DD-036) |
| `scylla_info() -> handle` | `{name, language, functions}` |
| `scylla_functions(zoom) -> handle` | all functions at a zoom altitude (0=intent,1=domain,2=detail) |
| `scylla_view(id, zoom) -> handle` | one function by stable id |
| `scylla_callers(id) -> handle` | stable ids that call `id` (call-graph navigation) |
| `scylla_rename(id, ptr, len) -> 0/-1` | rename a function (DD-005); -1 on a blank name / unknown id |
| `scylla_retype(id, ptr, len) -> 0/-1` | retype a function |
| `scylla_comment(id, ptr, len) -> 0/-1` | comment a function (may be empty) |
| `scylla_export() -> handle` | the (annotated) `.scylla` artifact bytes, to download |
| `scylla_merge(ptr, len) -> handle` | re-anchor the current annotations onto a re-analysis (DD-005); `{merged, flagged}` |
| `scylla_free(ptr, len)` | release a buffer |

A **string result** is returned as a `(ptr<<32 | len)` u64 (a BigInt in JS); the caller copies it
out of linear memory and then `scylla_free`s it. Buffers are exact-size `Box<[u8]>` so the
`(ptr,len)` free matches the allocation layout.

## Run

The turnkey way — the native single-binary head [`scylla-serve`](../scylla-serve) embeds this WASM
head and serves it + your artifact (no JVM, no toolchain):

```bash
cargo run -p scylla-serve -- crates/scylla-wasm/web/mathlib.scylla   # → http://127.0.0.1:8000/
cargo run -p scylla-serve -- my_program.scylla                       # navigate your own artifact
```

Or serve `web/` with anything (`cd web && python3 -m http.server` — `file://` can't fetch wasm).
Prebuilt `web/scylla_wasm.wasm` + `web/mathlib.scylla` are committed so it's turnkey; `./build.sh`
rebuilds them (then rebuild `scylla-serve`, which embeds the wasm).

## Verify (headless — no browser needed)

```bash
node web/verify.mjs             # loads the wasm + artifact, navigates, asserts PASS
```

`verify.mjs` uses the *same* WebAssembly API + marshaling as `index.html`, so a PASS there means
the browser demo works.

## Scope

**Navigate + annotate + export + merge**, all in the browser:

- list/zoom/navigate the call graph;
- rename/retype/comment (durable user facts, DD-005) and download the modified `.scylla` (DD-026)
  — re-load it and the renames survive;
- **merge a re-analysis** — re-anchor your annotations onto a rebuilt binary by *structural
  identity*, so a rename follows its function across an address shift / fresh ids (DD-005,
  fail-closed: a near-tie never anchors). **git-for-RE, client-side.**

End-to-end verified by `verify.mjs`: a rename → export → reload → **merge** round-trip (the rename
re-anchors onto a fresh-id rebuild).

Still future: engine verbs (`decompile`, which needs the JVM engine — not available client-side).
A *live* browser head over a serving core would use the Cap'n Proto RPC surface (DD-002, deferred —
shape-validated by `spike/rpc-shape`).
