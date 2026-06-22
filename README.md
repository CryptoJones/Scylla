# Scylla

**A hexagonal, adapter-headed reverse-engineering platform.**

Scylla wraps a proven reverse-engineering engine behind a **durable, transport-agnostic
reverse-engineering domain model** — the *body* — and exposes it through thin,
**disposable protocol adapters** — the *heads*.

Named for the six-headed sea monster of Homer's *Odyssey*: many heads, one immortal
body. Lop a head off and grow a new one. Today's head is an **MCP server** — so AI
agents can reverse-engineer binaries directly. When MCP is the CORBA of 2040, you
grow a new head and the body never notices.

## The idea

Reverse-engineering tools fossilize around the universal adapter of their era
(Ghidra is Java-shaped because the JVM was *the* cross-platform answer circa 2000).
You can't pick a technology that survives 20 years — so don't. Pick the right **seam**
and bet on the slowest-moving layer.

In reverse engineering, the slowest-moving layer is the **domain model itself** —
functions, basic blocks, cross-references, types, the call graph, symbols, decompiled
output, annotations. That vocabulary barely moved from IDA in the '90s to Ghidra in
the 2000s to today, and it won't move much in the next 20 years, because it isn't a
technology — it's the *shape of the problem*.

Scylla's architecture (ports-and-adapters / hexagonal):

- **The body** — a clean, minimal, transport-agnostic contract for the RE domain
  model, sitting on top of a proven engine (the engine is sacred; it is never
  rewritten).
- **The heads** — thin, sheddable protocol adapters (MCP first; REST/gRPC/whatever
  next) that project the body to whatever consumer the era demands. Each head is
  ~a few hundred lines and disposable; the body is the only bet you can't take back.

You cannot shim your way out of a bad core, so the design effort goes into the body.
The heads are cheap on purpose.

## Before → After

**Before** — the current GayHydra / Ghidra implementation Scylla refactors away from:
a Java monolith with the UI welded to the framework, the proven C++ decompiler reached
across a brittle serialized IPC seam (warts in red, the proven engine in green):

![GayHydra current architecture — the "before"](docs/before-gayhydra-architecture.png)

**After** — the hexagonal target Scylla builds toward: a durable **Rust core** holding the
RE domain model as the system's **narrow waist**, GayHydra demoted to a **droppable proven
engine** behind the engine-port, and disposable polyglot **heads** (MCP first) below the
client-port. The two ⟡ bands are the narrow waists; the model-artifact is the one bet you
can't take back:

![Scylla proposed hexagonal architecture — the "after"](docs/proposed-scylla-architecture.png)

The reasoning behind every box is recorded in [DesignDecisions.md](DesignDecisions.md) (all
33 decisions); the build path — prototype-first — is in [SprintPlanning.md](SprintPlanning.md).

## Status

Early — **design phase.** Sibling project to
[GayHydra](https://github.com/CryptoJones/GayHydra) (a hardened fork of NSA Ghidra,
which provides the proven engine Scylla wraps).

## Acknowledgements

Scylla stands on work it has no intention of replacing:

- **[Ghidra](https://github.com/NationalSecurityAgency/ghidra)** (NSA) — the proven
  reverse-engineering engine Scylla wraps, by way of the
  **[GayHydra](https://github.com/CryptoJones/GayHydra)** hardened fork. The engine is
  sacred: Scylla demotes it to a droppable producer behind the engine-port, never rewrites it.
- **[Cap'n Proto](https://capnproto.org)** — the serialization behind the durable
  model-artifact and the client-side RPC surface (DD-002). The artifact is the one bet
  Scylla can't take back, so it rests on a format built for schema evolution and bounded,
  memory-safe reads.
- **[Protocol Buffers](https://protobuf.dev)** over **[tonic](https://github.com/hyperium/tonic)**
  / **[Prost](https://github.com/tokio-rs/prost)**, on **[Tokio](https://tokio.rs)** — the
  gRPC engine-port seam to the sandboxed JVM engine-as-service (DD-009/040).
- The **[Rust](https://www.rust-lang.org)** project and its crate ecosystem — the language
  of the durable core.

Two serialization IDLs in one tree — Cap'n Proto on the model/client waist, Protocol
Buffers on the engine seam — is a deliberate, documented choice (see DD-002), not an accident.

## License

[Apache License 2.0](LICENSE) © Aaron K. Clark — matching Ghidra (Apache 2.0), the engine Scylla builds on.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
