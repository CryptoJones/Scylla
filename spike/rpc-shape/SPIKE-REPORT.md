# Spike: DD-002 RPC-shape — does the client port survive the wire it was chosen for?

**Verdict: GO.** The navigation-heavy client port (`scylla_port::Session`) projects **cleanly**
to a Cap'n Proto RPC `interface`, and **promise-pipelining works** — the exact capability the
format was chosen for. No port API change was needed. The DD-002 deferral of the *production*
RPC surface is now de-risked: the irreversible "narrow waist" holds its shape under the
transport it was designed around.

## Why this spike exists

DD-002 chose Cap'n Proto partly because the client port is **navigation-heavy** (get a function
→ its callers → their views — many small round-trips) and Cap'n Proto's **promise-pipelining**
collapses those. But we shipped the port and built heads on it while only ever consuming it
**in-process** — so the one bet Scylla says you can't take back (the body/port) had never been
stress-tested against its own design premise. This spike closes that validation gap *before*
the port API ossifies, without committing to the full production RPC layer.

## What was built (throwaway)

- `schema/port.capnp` — `interface Session { function(id) → Function; functions() → List(Function) }`
  and `interface Function { view() → …; callers() → List(Function) }`. The key move: lookups
  return **capabilities**, not data — the promise-pipelining seam.
- `src/main.rs` — server impls of those interfaces backed by an in-process `Session`
  (`Rc<RefCell<Session>>`), an in-memory two-party RPC (`tokio::io::duplex`), and a client that
  drives a **pipelined** `function(gcd).callers().view()` navigation, asserting it reproduces the
  in-process port. Run it: `cargo run`. Test: `cargo test`.

## Result

```
gcd's callers, in-process port : ["main"]
gcd's callers, over capnp RPC  : ["main"]      ← MATCH
function(gcd).callers() issued on the un-resolved capability → one round-trip (pipelined)
session.functions() list-all projects identically
```

## Findings — the port is wire-shaped

- **1:1 projection, zero port changes.** The port's surface is StableId-keyed and per-entity
  (`view(id)`, `callers(id)`, `functions()`), which maps directly onto capabilities (a `Function`
  cap == a `StableId` + a handle to the port). Nothing in the port had to change to be projected.
- **No wire-hostile patterns.** The port returns **owned** data (`FunctionView`, `Vec<StableId>`),
  not borrows or fat graph objects, and navigates by stable id — exactly what serializes and
  pipelines cleanly. The thing we worried about (chatty, reference-returning, in-process-only
  shapes baked into the irreversible layer) **is not present.**
- **Pipelining is real here.** `callers()` rode the un-resolved `function()` result, so the
  classic navigation chain is one network round-trip — the property that justified Cap'n Proto.
- **The sync/async boundary stays clean (DD-009).** The port is a pure synchronous model
  consumer; the RPC server is a thin async wrapper whose method bodies make sync port calls. The
  engine-side async (DD-019 job handle) is orthogonal and untouched.

## Scope / caveats (deferred with the production surface)

- Two read verbs projected (`view`, `callers`, `functions`). **Mutating verbs**
  (`rename`/`retype`/`comment`) weren't projected but are trivially wire-shaped — they take a
  `StableId` + a value and return `Result`, and `PortError::InvalidInput` (DD-021) maps straight
  to `capnp::Error`. **`decompile`** is engine-side (async, needs a live engine) — not part of a
  pure-port spike.
- Production concerns (schema versioning/evolution, auth/principals over the wire — DD-035,
  bounded reads on the RPC path — DD-036, transport choice) ride with the real surface, to be
  built when a **remote/networked head** (WASM browser — DD-028, or collaboration — DD-027)
  actually needs it. This spike says that build is **low-risk**, not that it's needed now.

## Recommendation

Keep DD-002's RPC line **"served in-process, capnp-RPC deferred"** — but mark the deferral
**validated**: the port shape is wire-ready, so building the full surface can wait for a real
remote head with confidence it won't force a body rewrite. Throw this spike away (or keep it as
the seed for the real `interface`).
