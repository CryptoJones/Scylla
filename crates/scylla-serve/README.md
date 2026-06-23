# scylla-serve — the native single-binary head (DD-028)

```
scylla-serve <artifact.scylla> [compare.scylla] [port]      # default port 8000
```

A **single, self-contained native binary** that serves the [WASM head](../scylla-wasm) + your
`.scylla` model-artifact over HTTP — so you `scylla-serve foo.scylla`, open the browser, and
navigate/annotate/merge/diff the model with **no JVM, no server runtime, no toolchain**. This is the
other half of DD-028 (the WASM head is the consumer; this is the "single native binary serving a
pre-built artifact with no JVM present" of Sprint 8).

- **Zero dependencies** — std only; a hand-rolled HTTP/1.1 static responder, thread-per-connection.
- The WASM head (`index.html` + `scylla_wasm.wasm`) is **baked in** at compile time (`include_*!`),
  so the binary is fully self-contained. The artifact is read at startup and served where the head
  fetches it (`/mathlib.scylla`).
- **Two-build diff, turnkey.** Pass a second `.scylla` and it is served at `/compare.scylla`; the
  head **auto-diffs** the base against it on boot (structural, address-independent — DD-017), so
  `scylla-serve old.scylla new.scylla` opens straight onto *what the recompile changed* (open
  ⊞ graph to see it painted on the call graph). Args are order-independent: a token that parses as
  a port is the port, one ending `.scylla` is the compare build.

```bash
cargo run -p scylla-serve -- crates/scylla-wasm/web/mathlib.scylla
#   → http://127.0.0.1:8000/   (navigate the bundled sample)
cargo run -p scylla-serve -- my_program.scylla 9000
#   → http://127.0.0.1:9000/   (navigate your own artifact)
cargo run -p scylla-serve -- old.scylla new.scylla 9000
#   → http://127.0.0.1:9000/   (auto-diff old vs new — what the rebuild changed)
```

If you rebuild the WASM head, rebuild this too (it embeds the prebuilt `scylla_wasm.wasm`).
