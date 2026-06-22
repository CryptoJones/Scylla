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
| `scylla_free(ptr, len)` | release a buffer |

A **string result** is returned as a `(ptr<<32 | len)` u64 (a BigInt in JS); the caller copies it
out of linear memory and then `scylla_free`s it. Buffers are exact-size `Box<[u8]>` so the
`(ptr,len)` free matches the allocation layout.

## Build + run

```bash
./build.sh                      # cargo build --target wasm32 --release + stage web/ + sample artifact
cd web && python3 -m http.server # then open http://localhost:8000  (file:// can't fetch wasm)
```

Prebuilt `web/scylla_wasm.wasm` + `web/mathlib.scylla` are committed so the demo is turnkey;
`build.sh` regenerates them.

## Verify (headless — no browser needed)

```bash
node web/verify.mjs             # loads the wasm + artifact, navigates, asserts PASS
```

`verify.mjs` uses the *same* WebAssembly API + marshaling as `index.html`, so a PASS there means
the browser demo works.

## Scope (v1)

Read-only **viewer** over a persisted artifact — list/zoom/navigate. Annotation + merge (which
the in-core port supports) and engine verbs (`decompile`) are future work; the pure
model-navigation surface is what compiles cleanly to WASM with no engine dependency. A *live*
browser head over a serving core would use the Cap'n Proto RPC surface (DD-002, deferred —
shape-validated by `spike/rpc-shape`).
