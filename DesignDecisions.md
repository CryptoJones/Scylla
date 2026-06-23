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

Settled below (`OPEN` → `DECIDED`); the per-DD entries carry the same status. **DD-009 and
DD-016 were reversed mid-session** — the initial embed / Kotlin-JVM call was traded for
**engine-as-service + a Rust core** under an explicit mandate from the project owner:

> *"Nobody is ever going to use it so it doesn't matter how long it takes. Let's do it right."*
> — Aaron K. Clark, 2026-06-21

With time off the table, the native-serving payoff (DD-016) wins, and the core↔engine seam is
recognized not as a wart but as the architecture's **second narrow waist** (the engine port).
The two stable waists — *engine-port* on the producer side, *model-artifact* on the consumer
side — leave everything pluggable above and below *both*. (See "Why It's Shaped This Way.")

**The contracts & model (what Scylla *is*):**
- **DD-026 / DD-015 — Persistence: own the format.** Canonical on-disk form is a clean,
  documented, versioned serialization of the *domain model*. Ghidra's `.gpr` is demoted to a
  disposable import/export interop adapter + the engine's private cache — **never canonical.**
  Binary input unchanged (bytes + auto-detected arch/base/loader hints).
- **DD-017 / DD-001 — Client port: data-centric, model-primary.** Exposes the
  **engine-independent domain model as a navigable graph** + a curated command set (`import`,
  `analyze`, `decompile`, `rename`, `retype`, `comment`, `diff`). The model: **rich type
  system; user facts first-class & durable (survive re-analysis); graphs (call graph, CFGs)
  computed, not stored** — "if a human RE says it out loud, it's in the model."
- **DD-020 — Altitude: focal-length / semantic-zoom.** One multi-resolution graph; every
  request carries a *detail level*. Domain vocabulary is the default; finer (p-code, bytes) is
  one zoom *down* (escape hatch); coarser *intent* is the consumer/agent's job, never in the
  port.
- **DD-002 — Schema: Cap'n Proto.** Zero-copy (the large model is navigated lazily), schema-
  first polyglot codegen + evolution, and promise-pipelining RPC for the navigation-heavy
  client port. First-class now that the core is Rust (the FlatBuffers lean was a JVM-era
  artifact).
- **DD-003 — IR: adopt P-code**, parked at the fine-zoom escape hatch — the one place the
  model is honestly engine-flavored; the domain level above it survives an engine swap.

**The inner plumbing — two narrow waists, pluggable on both sides:**
- **DD-009 — Engine integration: engine-as-service.** GayHydra runs as a separate JVM
  *producer* behind the engine-port protocol; the Rust core calls it. Navigation runs over the
  core's *materialized* model (in-core), so the seam carries only coarse ops — materialize,
  analyze, decompile — not per-zoom traffic. *(Reversed from the initial embed call.)*
- **DD-016 — Language: Rust core; heads polyglot.** The JVM is demoted to a transient analysis
  producer; the always-on serving/navigation core is **native** — WASM-able into a browser,
  embeddable as a library, distributable as a single binary. *(Reversed from Kotlin/JVM.)*
- **DD-011 — Engine: GayHydra** (the hardened fork — inherits Rec 18/19 + 33/34; it's ours).
- **DD-014 — Trust boundary: sandbox the engine.** With engine-as-service the sandbox wraps
  only the **engine producer** (the adversarial-binary parser); the Rust core sits *outside*
  the blast radius — a hostile binary can't reach it at all.

**Round 2 (2026-06-21) — the rest, locked.** Per the owner's call, *every remaining DD takes
its safest option* — be a faithful Ghidra wrapper, defer everything optional, ship one (MCP)
head — **except three taken deliberately bold: DD-004 + DD-005** (stable synthetic IDs + an
identity-anchored user/machine merge — because here "safe = copy Ghidra" inherits the very
flaw that loses analysts' work) **and DD-028** (native single-binary + WASM distribution — so
the Rust core's payoff isn't left on the table). Every DD is now DECIDED; the per-DD entries
below carry the choice + a *safe* / *bold* tag.

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
  artifact, so the always-on serving/navigation half can be lightweight — and, with the **Rust**
  core (DD-016), WASM-able into a browser, embeddable as a library, distributable as one binary.
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

## Cross-Decision Coherence (2026-06-21)

A 10,000-ft pass over all 33 decisions interacting as one system. The set holds together; in
three places the pieces actively reinforce each other, three tensions were resolved (folded
into the cited DDs), and one keystone risk carries the whole bet.

**Reinforcement loops (the design *wants* this shape):**
- **DD-004/005 is the same primitive as DD-027.** Stable IDs + identity-anchored merge is
  *both* how re-analysis avoids clobbering user facts *and* how two analysts' artifacts merge
  (git-for-RE). The bold exception pays off twice.
- **The Rust spine interlocks.** Native core (DD-016) + native/WASM distribution (DD-028) +
  droppable engine (DD-009) + heavy whole-framework engine (DD-010): light always-on consumer,
  heavy on-demand producer — each makes the others possible.
- **The hard work lands where it can't be shed.** Thin heads (DD-024/025) push the valuable
  agent-altitude design (DD-017/020) into the durable port, not a disposable adapter.

**Tensions resolved (see the cited DDs):**
- **Session vs droppable engine (DD-006 ↔ DD-009):** the durable session is the core's
  model-artifact; the engine's Program handle is ephemeral.
- **Zero-copy vs mutable merge (DD-002 ↔ DD-004/005):** Cap'n Proto is the persistence/transport
  *projection*; the live in-core model is a native mutable graph keyed on stable IDs.
- **One schema, two waists (DD-002 ↔ DD-009):** Cap'n Proto on the client/persistence side; a
  JVM-friendly wire on the engine-port side. Two formats by design.

**Keystone risk:** **DD-004's re-anchoring algorithm** — matching IDs across structural change.
The technical heart of the platform; prototype first to de-risk (see DD-004).

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
*Status:* **DECIDED (2026-06-21)** — **rich type system** (structs/unions/enums/pointers/arrays/function signatures); **user facts first-class & durable** (renames, types, comments survive re-analysis — see DD-005); **graphs (call graph, CFGs) computed/navigable, not stored.** In/out line: if a human RE says it out loud it's in the model; engine bookkeeping stays behind the engine port.

**DD-002 — Model contract & schema language.**
*Question:* How is the model *specified* as a stable, transport-agnostic contract —
protobuf? a custom IDL? JSON Schema? language-native types projected out?
*Tension:* the contract outlives every transport, so it must be schema-language-neutral
in spirit; but we need *one* canonical authoring form.
*Status:* **DECIDED (2026-06-21)** — **Cap'n Proto.** Zero-copy for the large, lazily-navigated model; schema-first polyglot codegen + evolution; promise-pipelining RPC fits the navigation-heavy client port. First-class now that the core is Rust (DD-016) — the FlatBuffers lean was a JVM-era artifact, and Cap'n Proto's weak JVM binding no longer applies *on this side* (the Rust↔JVM engine-port wire is separate — DD-009). **Resolution (coherence pass, 2026-06-21):** Cap'n Proto is the **persistence + transport projection** of the model; the *in-core working model* is a native mutable Rust graph keyed on the stable IDs (DD-004). Zero-copy buffers are read-optimized, so the live edit/merge representation is native and serializes *to* Cap'n Proto — the buffer is never the live model. **RPC surface (2026-06-22):** the navigation-heavy client port is **served in-process** — the heads drive `scylla_port::Session` directly (the MCP head marshals JSON-RPC ↔ port; the non-MCP client calls `Session` straight), so no Cap'n Proto RPC wire exists today (`model.capnp` is data `struct`s only; no `interface`, no `capnp-rpc`). The **promise-pipelining RPC** projection — for a *remote/networked* head — is **deferred** to a future adapter; Cap'n Proto remains the model-artifact **persistence** format now. The schema-choice rationale (promise-pipelining fits a navigation-heavy port) still holds; it just isn't realized as a live wire yet. **Deferral VALIDATED (2026-06-22), `spike/rpc-shape`:** the port was projected onto a throwaway Cap'n Proto RPC `interface` (`Session`/`Function` capabilities) and driven over a real two-party RPC — `function(gcd).callers().view()` pipelines (one round-trip) and reproduces the in-process port exactly, with **no port API change**. The port is StableId-keyed and returns owned data (no borrows / fat graph objects / chatty patterns), so it is wire-shaped. So the deferral is de-risked — the production surface can wait for a real remote head (DD-028 WASM / DD-027 collab) without risking a body rewrite.

**DD-003 — The IR.**
*Question:* Adopt Ghidra's **P-code** as the canonical IR, abstract over it, or define
our own? *Tension:* P-code is proven and architecture-neutral (huge win), but adopting
it couples the core to Ghidra's IR semantics — arguably fine (P-code *is* domain, not
technology), but it's a conscious bet. Defining our own IR is enormous scope.
*Status:* **DECIDED (2026-06-21)** — **adopt P-code** as the canonical IR, parked at the fine-zoom escape hatch (periphery, not spine). The one place the model is honestly engine-flavored; the domain level above it survives an engine swap.

**DD-004 — Entity identity & stability.**
*Question:* How are entities identified such that IDs survive re-analysis and user
edits? (address-based? content-hash? synthetic stable IDs?) *Tension:* re-running
analysis must not orphan a user's renames/retypes/comments.
*Status:* **DECIDED (2026-06-21) — *bold exception.*** **Synthetic stable IDs**, minted at first-sight; address is a mutable *attribute*, not the identity. Re-analysis re-anchors IDs to entities by structure/content so a user's renames/types/comments follow the *entity* when code shifts — the property that keeps the tool from losing work. (Safe-by-precedent here = Ghidra's address-keyed identity = the very thing that orphans edits; rejected.) **Keystone risk (coherence pass, 2026-06-21):** the *re-anchoring* algorithm — matching last run's IDs to this run's entities across structural change (a function that splits/merges, shifted code) — is the central technical bet of the whole platform; DD-005, DD-027, and "never lose the user's work" all stand or fall on it. Prototype this first to de-risk.

**DD-005 — Mutability & the edit/analysis merge.**
*Question:* Are model entities mutable in place? How do *user facts* (renames, types,
comments) compose with *machine facts* (re-analysis) without clobbering each other?
*Tension:* this is the classic RE-tool pain; get it wrong and analysis fights the user.
*Status:* **DECIDED (2026-06-21) — *bold exception.*** **User facts are edges onto the stable entity IDs (DD-004); re-analysis emits fresh machine facts that merge against those IDs — the user wins on conflict, non-conflicting machine updates flow through.** Not a blind overlay; a real identity-anchored merge. This is the differentiator: analysis never fights the user.

**DD-006 — State & session model.**
*Question:* Is the core session-based (a long-lived "program/project" handle holding
accumulated analysis) or stateless-per-call? How is that state created, evolved,
snapshotted? *Tension:* RE is deeply stateful; agents/clients need a handle, but
statefulness complicates the ports and scaling.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Session-based**: a long-lived program/project handle. **Resolution (coherence pass, 2026-06-21):** the *durable* session is the **core's model-artifact** (DD-026), **not** the engine's Ghidra Program handle — that handle is ephemeral scaffolding, materialized out of and dropped (DD-009). "Session-based" = the core holds the long-lived model; the engine stays as stateless as possible between analysis bursts, so it can be spun up and dropped without losing the session.

**DD-007 — Provenance & confidence.**
*Question:* Does every fact carry provenance (which analyzer/user produced it) and a
confidence? *Tension:* invaluable for AI consumers, diffing, and trust — but it bloats
the model. Opt-in vs always-on.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Omit from v1**; the schema (DD-002) stays additive so provenance/confidence can slot in later without a break. Don't bloat the model now.

**DD-008 — Contract versioning & capability negotiation.**
*Question:* How does the domain-model contract evolve without breaking heads? (semver
the contract; capability handshake per head; additive-only rules?)
*Status:* **DECIDED (2026-06-21) — *safe.*** **Semver the contract + additive-only changes + a per-head capability handshake.** The boring, proven schema-evolution discipline.

---

## B. The Engine — wrapping the proven Ghidra (the sacred part)

**DD-009 — Engine integration strategy. (keystone)**
*Question:* How does the core drive the proven engine? Options: (a) Ghidra **headless
subprocess** (analyzeHeadless + scripts); (b) **embed the Ghidra JVM in-process** and
call its API; (c) a **long-lived engine service** the core talks to over a private
protocol; (d) **FFI straight to the C++ decompiler** + reimplement the framework glue.
*Tension:* proximity/perf vs isolation vs effort. This decision constrains DD-016
(language/runtime) and most of B/C.
*Status:* **DECIDED (2026-06-21, revised)** — **engine-as-service** (option c): GayHydra runs as a separate JVM *producer* behind the engine-port protocol; the Rust core (DD-016) calls it. Navigation runs over the core's *materialized* model in-core, so the seam carries only coarse ops — materialize, analyze, decompile — not per-zoom traffic. The engine-port seam is the architecture's *second narrow waist*, not a wart. *Reverses the initial embed call* under the owner's "do it right, time is no constraint" mandate (see Decisions Locked). The C++ decompiler stays behind Ghidra's internal IPC, untouched. **Resolution (coherence pass, 2026-06-21):** the engine-port wire is **not** Cap'n Proto (its JVM binding is weak — DD-002); the Rust↔JVM seam uses a JVM-friendly protocol (gRPC / a small framed protocol). Two wire formats by design — one per waist: Cap'n Proto on the client/persistence side, a JVM-friendly one on the engine side.

**DD-010 — Engine surface: whole framework vs parts.**
*Question:* Do we wrap Ghidra's *entire* Java framework (loaders, analyzers, SLEIGH,
program DB, decompiler-via-IPC) as the engine, or extract only pieces? *Tension:*
whole-framework is fastest and most proven (P1) but drags the JVM in; piecemeal is
leaner but re-implements proven glue (violates P1).
*Status:* **DECIDED (2026-06-21) — *safe.*** **Wrap the whole Ghidra Java framework** as the engine (loaders, analyzers, SLEIGH, program DB, decompiler-via-IPC). Zero re-implemented glue; honors P1.

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
*Status:* **DECIDED (2026-06-21) — *safe.*** **Leave Ghidra's Java↔C++ decompiler IPC exactly as-is** inside the engine box. Never touch the proven historical pain.

**DD-013 — SLEIGH / processor specs.**
*Question:* Reuse Ghidra's SLEIGH spec language + compiled `.sla` specs wholesale?
(Near-certain *yes* — it's the crown-jewel ISA-decoupling — but confirm and define the
boundary for adding/overriding specs.)
*Status:* **DECIDED (2026-06-21) — *safe.*** **Reuse SLEIGH + the compiled `.sla` specs wholesale**, no overrides in v1. The crown-jewel ISA decoupling; touching it is pure downside.

**DD-014 — Process, isolation & trust boundary.**
*Question:* How many processes, and where is the trust boundary? Binaries are
**adversarial input** — the engine that parses them should be sandboxed/isolated from
the core and the heads. *Tension:* isolation vs latency vs complexity.
*Status:* **DECIDED (2026-06-21, revised)** — with engine-as-service (DD-009) the sandbox wraps just the **engine producer** (the adversarial-binary parser); the Rust core sits *outside* the blast radius — a hostile binary can't reach it at all. (Supersedes the embed-era "sandbox the whole unit" boundary.)

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
*Status:* **DECIDED (2026-06-21, revised)** — core in **Rust** (native). The JVM is demoted to a transient analysis *producer* (the engine service, DD-009); the always-on serving/navigation core is native — WASM-able into a browser, embeddable as a library, distributable as a single binary. Heads stay out-of-process & polyglot. *Reverses the initial Kotlin/JVM call* under the "do it right, time is no constraint" mandate.

**DD-017 — Inbound (driving) ports.**
*Question:* Define the verbs an outside consumer uses to drive RE — e.g. `import`,
`analyze`, `decompile(func)`, `disassemble`, `query(funcs|xrefs|symbols|types|search)`,
`annotate(rename|retype|comment)`, `navigate(callgraph|cfg)`, `diff`, `export`. What's
the verb set, and at what *altitude*? *Tension:* the right altitude for an **AI agent
to reason with** vs power-user fine control — this is the hard, valuable design work.
*Status:* **DECIDED (2026-06-21)** — data-centric, model-primary: the port exposes the engine-independent domain model as a navigable graph + a curated command set, *not* engine operations. Altitude per DD-020. **`diff` deepened (2026-06-22):** the structural diff now classifies **modified** functions, not just added/removed. A body change shifts a function's exact signature, so it falls out of the exact-match pass — but a second **call-graph propagation** round (`scylla_merge::diff_programs`, the binary-diffing standard) re-identifies it by its unique neighbourhood of already-matched callers/callees: recovered as `matched` if the body is actually unchanged (a signature-ambiguous twin the call graph disambiguates) or `changed` if the body differs. `SessionDiff` gains a `changed: [(here, there)]` list. Propagation is **iterated to a fixpoint** — each round's new pairings become anchors for the next, so a match chains through a freshly-recovered neighbour (a changed function whose only anchor also changed is recovered once that anchor is) — and is fail-closed every round (no live anchor / ambiguous neighbourhood → stays only_here/only_there, never guessed — WRONG=0). **Full matching ladder (2026-06-22 → -23):** the diff now climbs the *same* EXACT → PROPAGATION → **ANCHOR** → **BSIM** → **FUZZY** ladder the identity-anchored merge (DD-005) uses, reusing its matchers: ANCHOR pairs a leftover by a unique reciprocal Jaccard over its arch-independent feature set (string literals, imports, package-qualified callee names — the BinDiff/SIGMADIFF lever, ISA-stable); BSIM by weighted cosine over the Ghidra BSim feature vector (the strongest fuzzy signal, Ghidra's 0.7 match floor); FUZZY by mnemonic-mix cosine + structural closeness — each a reciprocal unique winner clearing threshold + margin, so a function survives a body edit that defeats structure *and* the call graph as long as a distinctive string, feature vector, or instruction mix persists. So a recovered `changed` is now anything the merger could re-anchor — the diff matcher is at **full parity with the merge engine**; only a function changed past **every** discriminator falls to only_here/only_there.

**DD-018 — Outbound (driven) ports.**
*Question:* What does the core need *from* the outside, as ports it depends on? Likely:
an **engine port** (decompile/analyze), a **storage port** (persist RE state), a
**binary-source port** (where bytes come from), maybe a **type-library / symbol-server
port**. Define them so the engine and storage are themselves swappable adapters.
*Status:* **DECIDED (2026-06-21) — *safe.*** **The minimal trio only — engine port, storage port, binary-source port.** No speculative type-library / symbol-server ports until a head needs one.

**DD-019 — Sync / async / streaming / cancellation.**
*Question:* Analysis is long-running; decompilation is per-function. Do ports support
async, progress streaming, and cancellation? *Tension:* simplicity vs the reality that
a 200 MB firmware analysis can't be a blocking call.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Synchronous request/response everywhere, except a job handle (submit → poll) for long-running `analyze`.** Defer streaming + fine-grained cancellation.

**DD-020 — Port granularity / chattiness.**
*Question:* Coarse high-level verbs (`decompile_and_summarize`) vs fine-grained
(`get_pcode_op`)? *Tension:* coarse is agent-friendly and network-cheap; fine is
powerful but chatty. Probably *both*, layered — but decide the primitive set.
*Status:* **DECIDED (2026-06-21)** — focal-length / semantic-zoom: one multi-resolution model, domain vocabulary as the default; finer = escape hatch (one zoom down); coarser intent = composed by the consumer/agent (one zoom up), never baked into the port.

**DD-021 — Error & failure model.**
*Question:* How do ports surface failure (malformed binary, decompile timeout, OOM on
a hostile input)? A typed error taxonomy the heads can faithfully translate.
*Status:* **DECIDED (2026-06-21) — *safe.*** **A small typed error taxonomy that faithfully mirrors Ghidra's own exception classes.** Pass-through, not a clever new taxonomy.

---

## D. The Adapters — the heads (disposable, six of them?)

**DD-022 — Which heads, in what order?**
*Question:* The first head is **MCP** (agent-facing — the differentiator: *AI agents
that reverse-engineer binaries*). After that — REST, gRPC, a CLI, a web UI, a
Ghidra-plugin interop head? *Tension:* MCP-first is the strategic bet; everything else
is sequencing.
*Status:* **DECIDED (2026-06-21) — *safe.*** **MCP only for v1.** One head = least surface, and it's the differentiator; REST/gRPC/CLI/UI all deferred (DD-023).

**DD-023 — Name the six heads.**
*Question:* Scylla has six heads — which six adapters define the v1 vision? (e.g.
MCP · REST · gRPC · CLI · Web UI · Ghidra-plugin?) A concrete, finite head-set keeps
scope honest.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Name MCP as head #1; leave the roster open.** "Six heads" is branding, not a v1 contract — committing to six now is premature scope.

**DD-024 — The MCP head surface.**
*Question:* Which RE verbs (DD-017) become MCP tools, at what granularity, with what
schemas — designed so an agent can *plan* a reverse-engineering session, not just poke
at primitives?
*Status:* **DECIDED (2026-06-21) — *safe.*** **Expose the DD-017 command set 1:1 as MCP tools, nothing more.** Mirror the port; don't invent agent-specific verbs until usage shows the need.

**DD-025 — Adapter-thinness enforcement.**
*Question:* How do we *enforce* P6 (no domain logic in heads)? (architecture tests,
a heads/core dependency boundary, code review rules?)
*Status:* **DECIDED (2026-06-21) — *safe.*** **A hard core→heads dependency boundary (heads depend on core, never the reverse) + an architecture test in CI.** Mechanical enforcement of P6.

---

## E. Platform / cross-cutting

**DD-026 — Persistence format & store.**
*Question:* What stores RE state (the program-DB equivalent)? Reuse Ghidra's DB, a new
format, an embedded DB, file-based? *Tension:* reuse (interop, DD-015) vs a clean,
documented, versioned contract we control.
*Status:* **DECIDED (2026-06-21)** — **own the format**: a clean, documented, versioned serialization of the domain model is canonical; `.gpr` is the engine's private cache + a disposable interop adapter (DD-015), never canonical.

**DD-027 — Collaboration / multi-user.**
*Question:* Shared projects (a Ghidra-Server equivalent) — in scope for v1, or
single-user first? *Status:* **DIRECTION SET (2026-06-21)** — the bespoke server *dissolves*: collaboration is **model-artifact sync** (git-for-RE — share/sync/diff/merge), a consequence of the narrow-waist (see "Why It's Shaped This Way"). v1 scope (2026-06-21) — *safe:* **single-user; collaboration is manual artifact export/sync** (git-for-RE by hand), no merge tooling yet. The mechanism (artifact sync) was already settled.

**DD-028 — Packaging & distribution.**
*Question:* How is Scylla shipped, given it bundles a heavy engine? (container image,
single binary + bundled JRE, a server you run?)
*Status:* **DECIDED (2026-06-21) — *bold exception.*** **Ship the serving/navigation core as a single native binary + a WASM build for browser heads (using DD-016); the heavy JVM engine is a separately-bundled / on-demand-fetched producer, not part of the always-on serving artifact.** The safe container+JRE path would bank none of the Rust payoff we paid for; this spends it. **WASM head REALIZED (2026-06-22), `crates/scylla-wasm`:** the client port compiles to `wasm32-unknown-unknown` and a browser navigates a `.scylla` model-artifact entirely client-side (the first out-of-process head — `web/index.html`, headless-verified by `web/verify.mjs`). A raw wasm32 C-ABI (no wasm-bindgen) keeps it toolchain-light. It navigates AND **annotates** (rename/retype/comment — durable user facts, DD-005) and **exports** the modified `.scylla` (DD-026) — re-load it and the renames survive. It even **merges a re-analysis** client-side — re-anchor the annotations onto a rebuilt binary by structural identity (DD-005, fail-closed), so a rename follows its function across fresh ids / an address shift (git-for-RE in the browser; verified by a rename→export→reload→merge round-trip in `web/verify.mjs`). And it **diffs** against another artifact (DD-017 `diff`, read-only via `scylla_diff`) — pairing functions by the same address-independent structural identity, so a local rename shows through across two builds (`euclid_gcd → gcd`), and a function whose **body changed** is re-identified as **modified** by call-graph propagation (not a spurious remove+add); the overview paints the diff (cyan renamed, amber modified, green added). The head now covers the port's **full client verb set** (navigate/annotate/zoom/merge/diff), only engine `decompile` remaining server-side. Still future: engine `decompile`; a *live* browser head over a serving core would add the Cap'n Proto RPC surface (DD-002, deferred — shape-validated by `spike/rpc-shape`). The **native single-binary serving build is done too** — `crates/scylla-serve`, a zero-dependency (std-only) binary that bakes in this WASM head and serves it + a `.scylla` artifact over HTTP with no JVM (Sprint 8's "a single static binary serves a pre-built artifact with no JVM present"). So both halves of DD-028 are realized. The browser demo (`web/index.html`) renders the **call graph as an actual directed graph** — callers → focus → callees with arrowheads in call direction, every node click-re-centres — and has **live function search** (`/` to focus, matches name + summary); both are pure presentation over the existing port verbs (no new ABI, no rebuild).

**DD-029 — Security model.**
*Question:* It parses adversarial binaries and exposes a network surface. Inherit the
GayHydra deserialization lessons; sandbox the engine; harden the heads; supply-chain
sign releases (cosign, as GayHydra does).
*Status:* **DECIDED (2026-06-21) — *safe.*** **Inherit GayHydra's posture wholesale**: sandbox the engine producer (DD-014), cosign releases, carry the Rec 18/19 deserialization hardening + Rec 33/34 IPC modernization. Reuse proven, invent nothing.

**DD-030 — Testing strategy.**
*Question:* How do we test a RE platform? Golden-binary corpus, decompiler-output
regression, a fixed multi-arch/compiler/opt-level recall corpus, contract conformance
tests per head.
*Status:* **DECIDED (2026-06-21) — *safe.*** **A golden-binary corpus + decompiler-output regression** (multi-arch/compiler/opt-level), plus per-head contract-conformance tests. Standard RE-tool discipline.

**DD-031 — Observability & performance.**
*Question:* Logging/metrics/tracing across the hexagon; and the core must not add
latency over the engine — decompile-result caching, lazy analysis.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Structured logging + decompile-result caching; defer tracing/metrics.** The cache is the one must-have — the core must never regress engine latency.

**DD-032 — Licensing & dependencies.**
*Question:* Apache-2.0 (decided — matches Ghidra). Confirm dependency-license
compatibility as the engine + adapter deps land; keep the NOTICE accurate.
*Status:* **DECIDED (2026-06-21) — *safe.*** **Apache-2.0** (matches Ghidra); keep NOTICE accurate as engine + adapter deps land. Effectively closed.

**DD-033 — Project governance.**
*Question:* Contribution model, issue/PR lanes, triage SLA — explicitly *not*
recreating the Ghidra PR-graveyard pathologies the GayHydra audit catalogued.
*Status:* **DECIDED (2026-06-21) — *safe.*** **A minimal CONTRIBUTING + clear issue/PR lanes + a triage SLA**, explicitly structured to avoid the Ghidra PR-graveyard the GayHydra audit catalogued. Copy GayHydra's discipline.

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

## G. Security & Testing Hardening — DECIDED 2026-06-21

The threat model fits in one sentence: **three inputs are hostile — the binary, the `.scylla`
artifact, and the MCP head's caller** — and every decision below defends one of those
boundaries. If you are reading this because you want to "just trust the input this once," you
are the reason this section exists.

**DD-034 — Engine sandbox: container baseline (refines DD-014).** The adversarial-binary
parser runs in a locked-down container: read-only rootfs, **no network**, dropped capabilities,
hard mem/CPU/wall-clock limits, **one binary per invocation**. The policy is a *named set of
knobs*, so tightening to raw OS primitives (seccomp/Landlock) or a microVM later costs nothing
at the core↔engine protocol — best isolation-per-effort, and it matches "the engine is a
droppable producer" (DD-009). Do **not** run the engine in-process with the core to "save a
fork": that hands a malformed PE a seat inside the Rust core, and the entire reason the hexagon
exists evaporates in a single `Segmentation fault`.

**DD-035 — MCP head exposure: stdio/local-trust v1 + an auth-ready identity seam (refines
DD-022).** v1 is stdio, single-user, **no authz** — the agent is launched by the user and
inherits the user's trust, like every other MCP server on the planet. We do **not** build a
networked auth subsystem (tokens, TLS, sessions, rate-limiting, key rotation) for a surface
with zero users; that is gold-plating a door nobody can knock on, and auth stacks fossilize
exactly like the era-bound adapters this architecture exists to shed. What we **do** build is
cheap and load-bearing: an **optional principal/author** threaded through the session and onto
every user fact — because provenance (DD-007) and collaboration (DD-027) need "who" regardless.
The core therefore stops assuming single-user; a future networked head supplies a real
principal without a rewrite. The genuinely *current* threat is **prompt injection through the
binary** — a hostile sample's strings and decompiled output are attacker-controlled text
flowing into an agent's context — so the head surfaces all analysis content as **clearly
delimited untrusted data, never as instructions**, and typed errors (DD-021) never leak engine
or host internals.

**DD-036 — Artifact-loader trust: untrusted by default (refines DD-029).** The `.scylla`
artifact becomes the **second** adversarial input the instant collaboration (DD-027) exists,
and *we wrote the loader*, so this surface is ours to answer for. Cap'n Proto buys memory
safety and amplification-bomb defense **only if you set the reader limits on purpose** —
`ReaderOptions::new()` defaults are a security decision you are otherwise making *by accident*;
pin explicit, documented traversal + nesting caps and reject anything that blows them. The
loader is **total: it never panics and never OOMs** — a malformed artifact is a typed error,
not a stack trace. Structural invariants are validated on load (ids unique, refs resolve or the
edge is dropped-and-flagged, lengths bounded). Soft faults **quarantine-and-flag** (one
dangling comment does not nuke a collaborator's whole artifact); cap-busting or structural
corruption **hard-rejects**. And a foreign artifact's facts **never rule** — they enter through
the `collaborate()` conflict path (DD-027), surfaced, never silently authoritative. "It's just
our own format, it's fine" is the sentence at the top of every parser CVE.

**DD-037 — Test corpus: tiered, pinned, structural oracle (refines DD-030).** Two ways a
corpus rots, both forbidden. (1) **Golden means pinned *bytes*, not regenerated** — rebuild
from source in CI and compiler codegen drift silently rewrites your "golden," at which point
your oracle lies to your face; commit the actual bytes and keep the generator only for *growing*
the set. (2) **Assert structure, not decompiled prose** — full-text diffs red-flag on every
Ghidra point release; the oracle is the function set, boundaries, call edges, and symbols,
which is also exactly what re-anchoring needs. Three deliberate tiers, **not** a combinatorial
arch×compiler×opt explosion: **Tier 0** (committed, tiny, every-CI — the DD-038 fuel),
**Tier 1** (pinned, nightly — breadth: a 32-bit arch + an exotic to flex SLEIGH, C++ and Go),
**Tier 2** (out-of-tree, fetch-by-hash, release lane — UPX-packed, malformed ELF/PE,
license-clean real binaries). **No malware in the repo. Ever.** Not "encrypted," not "in a
password zip" — not in the repo.

**DD-038 — Re-anchoring regression: the keystone's release gate (refines DD-030).** This is
*the* test; if it regresses, the platform's one promise (DD-004/005 — "analysis never loses
your work") is broken, so it gates releases — and you will **gate two different things
differently**, because conflating a safety invariant with a quality metric is precisely how
this test goes flaky or blind. **(1) `WRONG = 0` is a hard, never-relaxed invariant** across
every perturbation class — a single silent mis-attachment fails the build, full stop; that is
the DD-005 contract, not a knob you turn down when it's inconvenient on a Friday. **(2)
Survival % is a *ratcheted floor*, not a guessed number** — record current per-class survival
as the committed floor and fail on any drop; improving the matcher raises it. The floor is
enforced only where recovery is *promised* (same-opt re-analysis / minor edit); the hard
classes (O0→O2, cross-arch) enforce `WRONG=0` and **track recovery as informational** — we do
not gate a release on a number we have honestly labelled future work. Every run emits the
per-class correct/wrong/orphaned **scoreboard** — no silent caps, ever. The regression
exercises the **shipping `scylla-merge`** over the Tier-0 committed snapshots (engine-free,
CI-able), not the prototype's Python: test what ships, not what you wish you shipped.

**DD-039 — Fuzzing: fuzz what you wrote, sandbox what you wrap (refines DD-030).** The sharpest
line in this section: **do not fuzz the engine.** Ghidra/GayHydra is a 20-year C++/Java
codebase we have *decided* to treat as a sandboxed black box (DD-034) and never rewrite (P1);
fuzzing it is upstream's job and the sandbox is *our* containment — anything else is a fuzzing
campaign you will never finish, substituted for a boundary you already drew. We fuzz the
**three Rust seams we actually wrote and expose**, with cargo-fuzz/libFuzzer:
`fuzz_artifact_loader` (the primary — it is what turns DD-036's "total" from a hope into a
*proven* claim; property: total, and valid inputs round-trip), `fuzz_mcp_dispatch` (property:
never panics, always returns well-formed JSON-RPC, even on garbage), and `fuzz_snapshot_ingest`
(malformed or compromised engine output). Fuzzing is **not** a per-commit gate — that is how
you earn flaky, glacial CI; split it: **per-commit replays the committed crash/seed corpus**
(deterministic — a bug that returns fails the build, because the crash corpus is committed and
found stays found), **nightly runs real coverage-guided fuzzing** and files new crashes.
Assert *properties*, not "it didn't crash this time." The loader target gates v1.

These six refine DD-014/022/029/030 and are non-negotiable for any path that touches an
adversarial input. If a future contributor calls one of them "overkill for now," point them at
the binary that is, at this exact moment, engineered specifically to make them regret saying so.

---

## H. The engine-as-service — DECIDED 2026-06-21

**DD-040 — Engine-port transport: gRPC; engine-as-service is a STANDALONE JVM process
(refines DD-009 / DD-034).** The Rust core drives the engine over **gRPC** (a `.proto`
contract, `tonic` on the Rust side, grpc-java on the JVM). Chosen over a hand-rolled framed
protocol because DD-019 demands streaming + cancellation and DD-009 demands a *swappable*
producer — gRPC gives both for free, and "a small framed protocol" is a fiction that grows into
a buggy, single-language gRPC the instant those requirements land. Two IDLs in the tree
(protobuf on this seam, Cap'n Proto on the model/client side) is a deliberate, documented cost,
not an accident: the two waists have different constraints, and DD-002 already kept capnp off
this seam for its weak JVM binding.

The engine-as-service is a **standalone JVM process that uses Ghidra *headless as a library*** —
**not** a GUI plugin. This is the whole game: grpc-java + Netty inside Ghidra's notoriously
fussy plugin classloader is exactly where this design would die; a normal-classpath standalone
app sidesteps it, and a separate sandboxed process is what DD-014/DD-009 wanted anyway.
**De-risk it before betting the build** — a spike proving a standalone JVM stands up grpc-java
*and* drives Ghidra headless cleanly, the same way DD-004 re-anchoring was proven before the
core was built. If the spike fights us, the fallback is a lean framed protocol over a unix
socket — but we prove the standard path works before we abandon it.

**DD-041 — Cross-architecture re-anchoring rides ARCH-INDEPENDENT features, not the mnemonic
histogram (refines DD-038).** The fuzzy pass scores cosine over the instruction mix, which is the
right signal for an edit or a recompile but is **structurally ~0 across ISAs** — x86-64 and aarch64
share no mnemonics and no addresses, so a function recompiled for a different architecture is
invisible to it. That is not a tuning problem; it is the wrong feature for the job. The features
that *do* survive a cross-ISA recompile are the ones tied to the program's meaning, not its
encoding: **the string literals a function references and the library/imports it calls by name**
(`printf`, not the PLT address). This is the binary-diffing consensus — BinDiff anchors on imported
functions, SIGMADIFF chooses "strings and library calls" *because* they are stable across
optimizations, compilers, and architectures — and it is what the engine now extracts
(`Function.string_refs` / `Function.imports`, carried over both the snapshot path and the gRPC
wire). The matcher gains a third pass between exact and fuzzy: an **ANCHOR pass** that matches on
**Jaccard over the arch-independent set**, accepted only on a unique best clearing a high threshold
AND a wide runner-up margin. `WRONG = 0` is preserved the same way the other passes preserve it — a
near-tie is flagged, never guessed — and the anchor pass, by claiming the high-confidence
string/import matches first, exposed a latent fuzzy false positive (a function inlined away in the
new build latching onto a structurally similar CRT stub it happened to share common mnemonics with).
The fix is the other half of the binary-diffing standard: **reciprocal-best matching** — a fuzzy
match counts only if the candidate's *own* best match points back, which a one-directional
coincidence cannot satisfy. Measured on Tier-0: cross-arch goes from 0 to recovering the
string/import-bearing function (`main`) in both mathlib and strutil, `WRONG=0` held, edit classes
still 100%. A fourth **PROPAGATION** pass then spreads those confirmed matches along the **call
graph**: a function the other passes can't place is matched by its position relative to functions
already matched. The discriminator is deliberately NOT structural — x86 and aarch64 `gcd` are
indistinguishable by size/bb (all four leaves share `bb_count`, and size is misleading across the
ISA, so structure would *mis*-match), it is graph-context: self-recursion and matched-neighbour
agreement. That uniquely recovers `fib` (the only self-recursive callee of `main`) **both cross-arch
and cross-opt** (mathlib O0→O2 and x86→aarch64 each 20%→40%), while the genuinely symmetric leaves
(`gcd`/`factorial`/`sum_to`, all called once by `main`, no callees) stay flagged. `WRONG=0` is
preserved by the same discipline plus a subtle but essential rule: a lone surviving candidate must
out-score the **generic-neighbour baseline** by the margin — "only option left" is not evidence (the
true match may be inlined away), the trap that one-directional matches fall into. Gate floors
ratcheted to lock the cross-arch *and* recompile gains in. The remaining lever is the heavier Ghidra
Version Tracking integration. We did the de-risking research first (Perplexity deep-research over the
cross-ISA diffing literature — BinDiff/SIGMADIFF anchor on strings+imports, then propagate across the
call graph) rather than guessing the feature set or the algorithm.

**DD-042 — Ghidra Version Tracking: evaluated, NO-GO for cross-arch (de-risk spike, not a build).**
The functions DD-041 still can't re-anchor — symmetric arithmetic leaves and cross-architecture in
general — are the obvious candidates for Ghidra's Version Tracking subsystem. We **de-risked with a
spike before betting a multi-PR integration** (the warm-engine pattern), and the verdict is NO-GO.
VT runs headlessly fine (`spike/vt/ScyllaVtSpike.java`; two solved gotchas — the destination
read-only guard needs `-DSystemUtilities.isTesting=true`, and the reference correlator needs its
seeds `setAccepted()` first), but its correlators are **exact instruction / byte / mnemonic**
matchers: they are built for *version-to-version patch diffing*, where most functions are
byte-identical so the exact correlators seed the bulk and the reference correlator propagates to the
few changed. That is the **opposite** of Scylla's hard cases. Measured on mathlib (`WRONG=0`
throughout): recompile O0→O2 — VT recovers **0** user functions (nothing byte-identical to seed), vs
the four-pass matcher's 40%; cross-arch — VT recovers **0** (no shared bytes/instructions/mnemonics →
no seeds at all), vs 40%. On the edit case VT merely re-finds the byte-identical functions the exact
pass already gets. So VT would *underperform the matcher we already ship* on the cases that matter,
and duplicate it on the cases that don't. The real cross-arch lever is **BSim** (LSH over decompiler
p-code feature vectors — ISA-abstracting; in the dist as `VersionTrackingBSim`, a heavier separate
de-risk) or, for Go specifically, a **Go-aware producer** (extract Go's string blob + devirtualize
runtime calls so the existing anchor fires). VT *is* the right tool if Scylla ever targets near-
identical patch diffing (the classic CVE-patch use case) — filed there, not against the cross-arch gap.

**DD-043 — Go-aware producer: de-risked, GO (callee NAMES are the arch-independent lever).** The
corpus validation (DD-041 / `docs/corpus-findings.md`) found Go binaries recover **0** functions
cross-architecture: Go strings aren't NUL-terminated C strings and `fmt.Printf` isn't a dynamic
import, so the C-centric anchor never fires. The de-risk spike (`spike/go-producer/`) found the fix
and proved it. (1) Ghidra recovers Go function names from `.gopclntab` **even when the binary is
stripped** (`-s -w -trimpath`) — pclntab survives because the Go runtime needs it; measured, a
stripped Go 1.22 binary came back with 1 `FUN_` placeholder out of 1575. (2) A function's set of
**callee NAMES** is **arch-independent** (Jaccard 1.0 amd64↔arm64): `main.main` → `{fmt.Fprintf,
strconv.Atoi, runtime.convT64, main.fib, …}`. This is the Go analog of C imports, and richer (Go
statically links the runtime, so call targets are named). (3) Folding callee-names into the anchor
set recovers Go cross-arch **0 → 2/4** (`main.main` anchors, `main.fib` propagates), `WRONG=0`. The
one caveat is external: Ghidra's Go support lags the release — Go **1.26** crashes the
`GolangSymbolAnalyzer` (struct layout too new for GayHydra 26.3), Go **1.22** works perfectly; the
producer is viable for Ghidra-supported Go versions. **Built:** `ScyllaModel` emits
`Function.callee_names` (package-qualified names, over the wire + Cap'n Proto), folded into the
matcher's `anchor_set`. The honesty guard is a **dotted-name filter** (`'.'` present, not leading-`_`,
no `::`, not `FUN_*`): it captures Go's `importpath.Func` names — which survive stripping — and
excludes C's bare local names (which don't) and compiler artifacts (the i386 `__x86.get_pc_thunk.bx`,
C++ `operator.delete`), so the unstripped-C gate cannot cheat. Verified: C callee_names empty across
all 11 gate classes (floors unchanged, WRONG=0); the Rust matcher anchors on callee-names with
cosine=0 (unit test). The cheaper of the two cross-arch levers; BSim remains the heavier, still
un-de-risked alternative for the symmetric C leaves.

**DD-044 — BSim decompiler-signature similarity: de-risked, GO (the cross-arch lever for the
symmetric leaves).** The functions DD-041/042/043 still can't re-anchor cross-architecture are the
symmetric arithmetic *leaves* (`gcd`/`factorial`/`sum_to`): no strings, no imports, no callee-names,
mnemonic cosine 0, and — being leaves — nothing for propagation to lever from. BSim is the tool aimed
straight at this (LSH over the decompiler's p-code feature vectors, an ISA-abstracting IR), and the
DD-042 spike named it as the next lever. We **de-risked before betting a multi-PR integration** (the
warm-engine pattern): `spike/bsim/ScyllaBsimSpike.java` analyzes two binaries in-process and walks the
decompiler signature path Ghidra's own `CompareBSimSignaturesScript` uses
(`WeightedLSHCosineVectorFactory` + the cross-arch `lshweights_64` from
`GenSignatures.getWeightsFile(srcLang, dstLang)` + `DecompInterface.generateSignatures` →
`buildVector`), **no database needed** for the de-risk. Measured (`mathlib` x86-64→aarch64, O0): `main`,
`fib`, `factorial`, and `sum_to` each match their cross-arch twin at **cosine 1.000** (significance
22–43, reciprocal-best) — where mnemonic cosine is 0 — and the one-opcode-apart pair stays distinct
(`factorial→factorial 1.000` vs `factorial→sum_to 0.711`, margin 0.289). This lifts the cross-arch
class from the matcher's 40% (main+fib) to **80%** (+ factorial + sum_to). The lone miss is `gcd`: the
modulo idiom decompiles to materially different p-code per ISA (x86 `DIV`-remainder vs aarch64
`SDIV`+`MSUB`), so its cross-arch self-similarity is **0.120** — *below* its 0.310 to the accumulator
leaves — and under the gate it **flags fail-closed** (sub-threshold, non-reciprocal), `WRONG=0`
preserved. **The integration constraint is non-negotiable:** gate on similarity (≥0.7) **and**
reciprocal-best **and** a significance floor — never raw argmax (which emits a spurious
`gcd→factorial` pick). That is exactly Scylla's existing pass-3 reciprocal-best + beat-the-baseline
discipline; reciprocal-best is load-bearing because `factorial→sum_to 0.711` clears a bare 0.7 floor
on its own. `gcd`-class division/modulo leaves remain out of reach of *every* current signal,
including BSim — honest, fail-closed coverage, recorded not papered over. See
[spike/bsim/SPIKE-REPORT.md](spike/bsim/SPIKE-REPORT.md); `./spike/bsim/run-spike.sh` reproduces it in
~8s and is the Go-forward regression artifact for a future cross-arch BSim pass.

**Built (DD-044, 3 slices).** (1) **Matcher** — `scylla-merge` Pass 4 (BSIM, after propagation):
weighted cosine over `Function.bsim_vector`, accepted only on a unique best clearing sim≥0.7,
beating the runner-up by a margin, AND reciprocal-best (the same WRONG=0 discipline as fuzzy; a
too-small vector defers as a significance proxy). No-op when the vector is empty, so the four prior
passes and the gate classes are untouched. (2) **Wire** — the vector rides the whole path:
`model.capnp` (`BsimFeature` + `Function.bsimVector`, round-tripped by `scylla-schema`),
`engine.proto` (`FunctionChunk.bsim_vector`, carried by `scylla-engine`), and `scylla-ingest`
(snapshot JSON). `weight` is the f32 bits of the coefficient, kept integral so the model stays
Eq/Hash and round-trips exactly. (3) **Producer** — a standalone `ScyllaBsim` extractor (the
decompiler-signature path: `WeightedLSHCosineVectorFactory` + the language's weights +
`generateSignatures`→`buildVector`→`getEntries`) deliberately kept OUT of the OSGi-shared
`ScyllaModel` (confined to `ghidra.program.model.*`): the BSim *computation* lives with the warm
worker like import+analyze does, while `ScyllaModel` only *serializes* the vector it is handed, so
the cold path degrades to empty. `EngineServer` compiles `ScyllaBsim` in the warm `javac` and parses
the vector into the gRPC chunk. **Proven end-to-end on real mathlib:** `factorial` and `sum_to`
re-anchor x86-64↔aarch64 — the symmetric leaves no other signal can place — while `gcd` (modulo:
cross-arch-distinct p-code) stays flagged; **cross-arch recovery 40% → 80%, WRONG=0** (the gate floor
is ratcheted to 0.80 to lock it in). **strutil's x86-64↔aarch64 corpus now carries vectors too** —
BSim recovers ALL of strutil's string leaves (`my_strlen`/`my_reverse`/`count_vowels`) cross-arch,
lifting it **25% → 100%** (`WRONG=0`, floor ratcheted to 1.0); the string loops decompile to
consistent cross-arch p-code, no `gcd`-style holdout.

**i386 cross-*width* BSim: de-risked, NO-GO** (`spike/bsim/run-spike.sh <x86-64> <i386>`). Unlike the
64↔64 cross-arch case, 32↔64 makes the symmetric leaves COLLAPSE: `factorial→factorial` and
`factorial→sum_to` both score 0.642 (margin **0.000** — indistinguishable, vs 0.289 cross-arch), and
`main` drops to 0.495. Gated, only `gcd`(1.0)+`fib`(0.709) match (2/5); `main`/`factorial`/`sum_to`
flag — `WRONG=0` held only because the gate rejects the collapsed pair (naive argmax = 1 WRONG). And
that is BEST case: the spike used the `lshweights_64_32` cross-width weights for both, but the producer
emits per-arch weights (`_64` vs `_32`), so live would be worse — and making it work would require the
producer to know the target arch. Marginal gain (the four-pass matcher already recovers main+fib at
40% cross-width) for real complexity → not worth it. The cold `dump_model` path (OSGi can't see BSim,
so it emits no vectors) remains the only open BSim lever — a clean no-op today.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
