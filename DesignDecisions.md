# Scylla — Design Decisions

The open decisions required to build **Scylla** — a first-class reverse-engineering
platform, built ground-up on **hexagonal architecture** (ports & adapters), wrapping
a proven RE engine (Ghidra / GayHydra) without rewriting it.

This file is the **agenda**, not the answers. Every entry below is a decision we
still have to *make*. As we decide each one, we convert it from `OPEN` to `DECIDED`
and record the choice + the rationale inline (lightweight ADR style). Nothing here
is settled yet.

> **Why this shape.** The lesson behind Scylla: you can't pick a *technology* that
> survives 20 years — every universal adapter (Java, CORBA, MCP) fossilizes. You pick
> the right *seam* and bet on the slowest-moving layer. So the decisions are weighted:
> the **core domain model** is the one bet we can't take back, and most effort goes
> there; the **adapters** are meant to be cheap and disposable.

---

## Decisions Locked (2026-06-21)

First working session. These are settled (`OPEN` → `DECIDED`); the per-DD entries below
carry the same status. The two **outer port contracts** (storage-in, client-out) and the
**inner engine/language** plumbing are now fixed; the rest still hangs off them.

**The two outer contracts (what Scylla *is*):**
- **DD-026 / DD-015 — Persistence: own the format.** The canonical on-disk form is a clean,
  documented, versioned serialization of the *domain model*. Ghidra's `.gpr` is demoted to
  (i) the embedded engine's private cache (behind the engine port) and (ii) a disposable
  import/export interop adapter — **never the canonical format.** Binary input is unchanged
  (bytes + auto-detected arch/base/loader hints).
- **DD-017 / DD-001 — Client port: data-centric, model-primary.** The port exposes the
  **engine-independent domain model as a navigable graph** plus a curated command set
  (`import`, `analyze`, `decompile`, `rename`, `retype`, `comment`, `diff`). Clients see the
  model ("function F, its decompilation, its callers"), never engine operations.
- **DD-020 — Altitude: the focal-length / semantic-zoom model.** One multi-resolution graph;
  every request carries a *detail level*. The **domain vocabulary is the default resting
  altitude**; finer (instructions, p-code, bytes) is one zoom *down* (an escape hatch);
  coarser *intent* is one zoom *up*, composed by the **consumer/agent**, never baked into the
  port. (Established names: *semantic zoom* + *level-of-detail / multi-resolution model*.)

**The inner engine/language plumbing (forced largely by the contracts):**
- **DD-009 — Engine integration: embed in-process.** The core embeds the engine and calls
  its API in-process — the semantic-zoom port demands constant fine-grained navigation that
  would die across a core↔engine seam. The C++ decompiler stays behind Ghidra's internal
  IPC, untouched (P1).
- **DD-016 — Language: Kotlin / JVM core; heads polyglot.** Embedding puts the core in the
  Ghidra JVM, so the core is Kotlin. **Only the core pays the JVM tax** — the adapter heads
  are out-of-process, any language (Rust/Go/TS), projecting the client port.
- **DD-011 — Engine: GayHydra** (the hardened fork — inherits Rec 18/19 + 33/34; it's ours).
- **DD-014 — Trust boundary: sandbox the unit.** The sandbox wraps the **whole core+engine
  process**; the heads live *outside* it and reach it only through the client port. Boundary
  is `core+engine ⟷ heads/host`, not `core ⟷ engine` — adversarial binaries are contained
  without re-introducing the seam. In-process speed *and* isolation.

**Still open** (now constrained by the above): the exact domain-model entity set (DD-001),
the contract schema language (DD-002), the IR choice (DD-003 — leans P-code via the embed),
and the rest of A / D / E.

---

## Why It's Shaped This Way — the model as a narrow waist

The reference answer for "why did Scylla do X." The whole architecture follows from one
structural choice: **the domain model is not data *inside* Scylla — it is the narrow waist
of the system.** A single stable, portable, engine-independent, zero-copy artifact, with
*producers* above it and *consumers* below it, everything on both sides pluggable. (The same
move IP made for networking, or the file/byte-stream made for Unix: one stable thing in the
middle, infinite variety on either side.)

That single move — decoupling every producer from every consumer through the model-artifact —
is *why* the design looks the way it does, and it dissolves a whole cluster of sub-problems at
once, because they were all symptoms of producer↔consumer coupling in the old monolith:

- **Engine-swap (DD-009/011).** The engine sits *above* the waist as one producer. Swapping it
  (or running several) is a pluggable concern, not a rewrite. Today it's GayHydra; the waist
  doesn't care.
- **Consume-side portability (DD-016).** Everything *below* the waist consumes a portable
  artifact, so the always-on serving/navigation half can be lightweight — and (with a native
  core) WASM-able into a browser, embeddable as a library, distributable as a single binary.
  The heavy JVM/engine becomes a *transient producer* you spin up to analyze and then drop.
- **Collaboration / multi-user (DD-027).** The Ghidra-Server subsystem *disappears.* A
  shareable, mergeable model artifact makes collaboration **git for reverse engineering** —
  share, sync, diff, merge two analysts' work. No bespoke collaboration server.
- **Independent scaling.** Producing (analyze: heavy, one binary at a time) and consuming
  (serve: light, massively concurrent) are opposite workloads. The artifact lets each scale to
  its own shape — analysis on a beefy box or a worker fleet, serving from featherweight nodes.
- **Agent fan-out.** The model is read-only and zero-copy, so **N agents read the same model
  concurrently with zero engine contention** — a *swarm* on one analyzed binary. This is what
  makes "AI agents reverse-engineering binaries" actually scale.
- **Caching / reuse / distribution.** The model is a *compiled* RE artifact — cache it, ship it,
  version it, reopen it instantly with no re-analysis. Analyze once, consume forever, everywhere.
- **Testability.** The consume side tests against fixed model artifacts with no engine in the
  loop — fast, deterministic, hermetic.

The monolith (`docs/architecture/` — the "before") had every one of these knotted together
inside the Java-framework slice. The waist severs the whole knot in a single cut. **When a
"why did you do it this way" question comes up, the answer almost always traces back to here:
the model is the waist; everything else is a pluggable producer or consumer.**

---

## Guiding principles (constraints on every decision — not themselves open)

- **P1. The engine is sacred.** The proven C++ decompiler (and the analysis it
  depends on) is decades of congealed correctness. We never rewrite it. We wrap it.
- **P2. Durable core, disposable heads.** A stable, transport-agnostic RE domain
  model at the center; thin, sheddable protocol adapters at the edges.
- **P3. Bet on the slowest-moving layer.** The RE *domain model* (functions, blocks,
  xrefs, types, the call graph, decompiled output) is ~30 years stable; protocols
  churn every 5–10. Marry the model; keep adapters polyamorous.
- **P4. Relocate volatility to the edges.** Everything that will change in 20 years
  (UI, protocol, the era's universal adapter) lives in a head you can peel.
- **P5. You can't shim your way out of a bad core.** Adapters are trivial; the model
  is irreplaceable. Agonize over the core; make the heads cheap.
- **P6. No domain logic in adapters.** A head is pure translation between its protocol
  and the core's ports. If logic leaks into a head, the core is wrong.

---

## A. The Core — the RE domain model (the body)

**DD-001 — Domain-model scope.**
*Question:* What entities and relations are in the canonical model? Candidate set:
program, address spaces, memory blocks/segments, bytes, symbols, functions, basic
blocks, instructions, the IR, data types, references (xrefs), the call graph, CFGs,
decompiled output, comments/annotations, bookmarks, equates, stack frames.
*Tension:* minimal-but-complete vs kitchen-sink. Too small and adapters re-derive;
too big and the contract ossifies around accidents.
*Status:* OPEN.

**DD-002 — Model contract & schema language.**
*Question:* How is the model *specified* as a stable, transport-agnostic contract —
protobuf? a custom IDL? JSON Schema? language-native types projected out?
*Tension:* the contract outlives every transport, so it must be schema-language-neutral
in spirit; but we need *one* canonical authoring form.
*Status:* OPEN.

**DD-003 — The IR.**
*Question:* Adopt Ghidra's **P-code** as the canonical IR, abstract over it, or define
our own? *Tension:* P-code is proven and architecture-neutral (huge win), but adopting
it couples the core to Ghidra's IR semantics — arguably fine (P-code *is* domain, not
technology), but it's a conscious bet. Defining our own IR is enormous scope.
*Status:* OPEN.

**DD-004 — Entity identity & stability.**
*Question:* How are entities identified such that IDs survive re-analysis and user
edits? (address-based? content-hash? synthetic stable IDs?) *Tension:* re-running
analysis must not orphan a user's renames/retypes/comments.
*Status:* OPEN.

**DD-005 — Mutability & the edit/analysis merge.**
*Question:* Are model entities mutable in place? How do *user facts* (renames, types,
comments) compose with *machine facts* (re-analysis) without clobbering each other?
*Tension:* this is the classic RE-tool pain; get it wrong and analysis fights the user.
*Status:* OPEN.

**DD-006 — State & session model.**
*Question:* Is the core session-based (a long-lived "program/project" handle holding
accumulated analysis) or stateless-per-call? How is that state created, evolved,
snapshotted? *Tension:* RE is deeply stateful; agents/clients need a handle, but
statefulness complicates the ports and scaling.
*Status:* OPEN.

**DD-007 — Provenance & confidence.**
*Question:* Does every fact carry provenance (which analyzer/user produced it) and a
confidence? *Tension:* invaluable for AI consumers, diffing, and trust — but it bloats
the model. Opt-in vs always-on.
*Status:* OPEN.

**DD-008 — Contract versioning & capability negotiation.**
*Question:* How does the domain-model contract evolve without breaking heads? (semver
the contract; capability handshake per head; additive-only rules?)
*Status:* OPEN.

---

## B. The Engine — wrapping the proven Ghidra (the sacred part)

**DD-009 — Engine integration strategy. (keystone)**
*Question:* How does the core drive the proven engine? Options: (a) Ghidra **headless
subprocess** (analyzeHeadless + scripts); (b) **embed the Ghidra JVM in-process** and
call its API; (c) a **long-lived engine service** the core talks to over a private
protocol; (d) **FFI straight to the C++ decompiler** + reimplement the framework glue.
*Tension:* proximity/perf vs isolation vs effort. This decision constrains DD-016
(language/runtime) and most of B/C.
*Status:* **DECIDED (2026-06-21)** — embed the engine in-process (the semantic-zoom port needs in-process navigation; a service would re-create the chatty seam on the hot path). The C++ decompiler stays behind Ghidra's internal IPC, untouched.

**DD-010 — Engine surface: whole framework vs parts.**
*Question:* Do we wrap Ghidra's *entire* Java framework (loaders, analyzers, SLEIGH,
program DB, decompiler-via-IPC) as the engine, or extract only pieces? *Tension:*
whole-framework is fastest and most proven (P1) but drags the JVM in; piecemeal is
leaner but re-implements proven glue (violates P1).
*Status:* OPEN.

**DD-011 — Build on GayHydra or stock Ghidra?**
*Question:* Is the wrapped engine **GayHydra** (the hardened fork — inherits the Rec
18/19 deserialization hardening and Rec 33/34 IPC modernization) or upstream Ghidra?
*Tension:* GayHydra gives us the security/IPC hardening for free, but couples Scylla to
the fork's cadence; upstream is more standard but unhardened.
*Status:* **DECIDED (2026-06-21)** — **GayHydra** (inherit the Rec 18/19 + 33/34 hardening; it's ours).

**DD-012 — Decompiler boundary.**
*Question:* Leave Ghidra's Java↔C++ decompiler IPC *as-is* inside the engine box, or
reach the C++ decompiler more directly? *Tension:* the IPC is proven (P1) — almost
certainly leave it — but it's the historical pain; do we ever touch it?
*Status:* OPEN.

**DD-013 — SLEIGH / processor specs.**
*Question:* Reuse Ghidra's SLEIGH spec language + compiled `.sla` specs wholesale?
(Near-certain *yes* — it's the crown-jewel ISA-decoupling — but confirm and define the
boundary for adding/overriding specs.)
*Status:* OPEN.

**DD-014 — Process, isolation & trust boundary.**
*Question:* How many processes, and where is the trust boundary? Binaries are
**adversarial input** — the engine that parses them should be sandboxed/isolated from
the core and the heads. *Tension:* isolation vs latency vs complexity.
*Status:* **DECIDED (2026-06-21)** — sandbox the **whole core+engine process**; heads live outside it and reach it only via the client port. Boundary = `core+engine ⟷ heads/host`, not `core ⟷ engine`. In-process speed *and* isolation.

**DD-015 — Interop with existing Ghidra projects.**
*Question:* Can Scylla open / round-trip existing Ghidra databases (`.gpr`, packed
files)? *Tension:* a migration path wins existing users, but binds us to Ghidra's
storage format (and its deserialization surface — see security).
*Status:* **DECIDED (2026-06-21)** — `.gpr` is an import/export interop adapter **and** the engine's private cache — never the canonical store (see DD-026).

---

## C. The Ports — the hexagonal seam

**DD-016 — Language & runtime for the core (and adapters). (keystone)**
*Question:* What does the *core* run on? Options: (a) **stay on the JVM** (Kotlin/Java
— the engine is Java, so this avoids a process boundary and reuses Ghidra's API
directly); (b) **core in Rust/Go**, talking to the Java engine as a service (collapses
DD-009 to option c); (c) polyglot. *Tension:* engine-proximity (JVM) vs a modern
systems language — and note P1 (engine is sacred = Java) pulls hard toward a JVM core,
which conflicts with the "kill the seam in Rust" instinct. **This is the single most
consequential decision; it interacts with DD-009/010.**
*Status:* **DECIDED (2026-06-21)** — core in **Kotlin/JVM** (embedding requires it). Only the core pays the JVM tax; the adapter heads are out-of-process and polyglot (Rust/Go/TS).

**DD-017 — Inbound (driving) ports.**
*Question:* Define the verbs an outside consumer uses to drive RE — e.g. `import`,
`analyze`, `decompile(func)`, `disassemble`, `query(funcs|xrefs|symbols|types|search)`,
`annotate(rename|retype|comment)`, `navigate(callgraph|cfg)`, `diff`, `export`. What's
the verb set, and at what *altitude*? *Tension:* the right altitude for an **AI agent
to reason with** vs power-user fine control — this is the hard, valuable design work.
*Status:* **DECIDED (2026-06-21)** — data-centric, model-primary: the port exposes the engine-independent domain model as a navigable graph + a curated command set, *not* engine operations. Altitude per DD-020.

**DD-018 — Outbound (driven) ports.**
*Question:* What does the core need *from* the outside, as ports it depends on? Likely:
an **engine port** (decompile/analyze), a **storage port** (persist RE state), a
**binary-source port** (where bytes come from), maybe a **type-library / symbol-server
port**. Define them so the engine and storage are themselves swappable adapters.
*Status:* OPEN.

**DD-019 — Sync / async / streaming / cancellation.**
*Question:* Analysis is long-running; decompilation is per-function. Do ports support
async, progress streaming, and cancellation? *Tension:* simplicity vs the reality that
a 200 MB firmware analysis can't be a blocking call.
*Status:* OPEN.

**DD-020 — Port granularity / chattiness.**
*Question:* Coarse high-level verbs (`decompile_and_summarize`) vs fine-grained
(`get_pcode_op`)? *Tension:* coarse is agent-friendly and network-cheap; fine is
powerful but chatty. Probably *both*, layered — but decide the primitive set.
*Status:* **DECIDED (2026-06-21)** — focal-length / semantic-zoom: one multi-resolution model, domain vocabulary as the default; finer = escape hatch (one zoom down); coarser intent = composed by the consumer/agent (one zoom up), never baked into the port.

**DD-021 — Error & failure model.**
*Question:* How do ports surface failure (malformed binary, decompile timeout, OOM on
a hostile input)? A typed error taxonomy the heads can faithfully translate.
*Status:* OPEN.

---

## D. The Adapters — the heads (disposable, six of them?)

**DD-022 — Which heads, in what order?**
*Question:* The first head is **MCP** (agent-facing — the differentiator: *AI agents
that reverse-engineer binaries*). After that — REST, gRPC, a CLI, a web UI, a
Ghidra-plugin interop head? *Tension:* MCP-first is the strategic bet; everything else
is sequencing.
*Status:* OPEN.

**DD-023 — Name the six heads.**
*Question:* Scylla has six heads — which six adapters define the v1 vision? (e.g.
MCP · REST · gRPC · CLI · Web UI · Ghidra-plugin?) A concrete, finite head-set keeps
scope honest.
*Status:* OPEN.

**DD-024 — The MCP head surface.**
*Question:* Which RE verbs (DD-017) become MCP tools, at what granularity, with what
schemas — designed so an agent can *plan* a reverse-engineering session, not just poke
at primitives? *Status:* OPEN.

**DD-025 — Adapter-thinness enforcement.**
*Question:* How do we *enforce* P6 (no domain logic in heads)? (architecture tests,
a heads/core dependency boundary, code review rules?)
*Status:* OPEN.

---

## E. Platform / cross-cutting

**DD-026 — Persistence format & store.**
*Question:* What stores RE state (the program-DB equivalent)? Reuse Ghidra's DB, a new
format, an embedded DB, file-based? *Tension:* reuse (interop, DD-015) vs a clean,
documented, versioned contract we control.
*Status:* **DECIDED (2026-06-21)** — **own the format**: a clean, documented, versioned serialization of the domain model is canonical; `.gpr` is the engine's private cache + a disposable interop adapter (DD-015), never canonical.

**DD-027 — Collaboration / multi-user.**
*Question:* Shared projects (a Ghidra-Server equivalent) — in scope for v1, or
single-user first? *Status:* **DIRECTION SET (2026-06-21)** — the bespoke server *dissolves*: collaboration is **model-artifact sync** (git-for-RE — share/sync/diff/merge), a consequence of the narrow-waist (see "Why It's Shaped This Way"). Whether v1 ships merge tooling or stays single-user-first is still open; the *mechanism* is settled.

**DD-028 — Packaging & distribution.**
*Question:* How is Scylla shipped, given it bundles a heavy engine? (container image,
single binary + bundled JRE, a server you run?) *Status:* OPEN.

**DD-029 — Security model.**
*Question:* It parses adversarial binaries and exposes a network surface. Inherit the
GayHydra deserialization lessons; sandbox the engine; harden the heads; supply-chain
sign releases (cosign, as GayHydra does). *Status:* OPEN.

**DD-030 — Testing strategy.**
*Question:* How do we test a RE platform? Golden-binary corpus, decompiler-output
regression, a fixed multi-arch/compiler/opt-level recall corpus, contract conformance
tests per head. *Status:* OPEN.

**DD-031 — Observability & performance.**
*Question:* Logging/metrics/tracing across the hexagon; and the core must not add
latency over the engine — decompile-result caching, lazy analysis. *Status:* OPEN.

**DD-032 — Licensing & dependencies.**
*Question:* Apache-2.0 (decided — matches Ghidra). Confirm dependency-license
compatibility as the engine + adapter deps land; keep the NOTICE accurate. *Status:*
OPEN (mostly settled — Apache 2.0).

**DD-033 — Project governance.**
*Question:* Contribution model, issue/PR lanes, triage SLA — explicitly *not*
recreating the Ghidra PR-graveyard pathologies the GayHydra audit catalogued.
*Status:* OPEN.

---

## F. Sequencing & dependencies

Not every decision is equal or independent. Rough order:

1. **Keystones first — DD-016 (language/runtime) + DD-009 (engine integration).**
   These two gate almost everything else; they're entangled (the engine being Java
   pulls the core toward the JVM).
2. **Then the core — A (DD-001…DD-008).** The model is the irreplaceable bet (P5);
   it can't be decided well until we know how we reach the engine.
3. **Then the ports — C (DD-017…DD-021).** The ports project the core; design them
   once the model exists.
4. **Then the first head — D (DD-022/DD-024, MCP).** Cheap and disposable by design;
   it should fall out of the ports.
5. **Cross-cutting (E) rides alongside** and is revisited as the above land.

> Working agreement: we take these roughly in the above order, decide each one
> explicitly, and write the choice + rationale back into this file (OPEN → DECIDED).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
