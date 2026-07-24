# Scylla — Threat Model

This is the deliberate seam-by-seam pass [SECURITY.md](SECURITY.md) promised, not a release-time
afterthought. It exists because Scylla's entire job is to ingest things engineered to hurt it. If
you are about to call a control here "overkill for now," go read the last paragraph first.

Grounded in the decisions, not vibes: every mitigation cites the DD it comes from
([DesignDecisions.md](DesignDecisions.md)); every **GAP** is a real hole found by reading the
code on `main`, filed in [BACKLOG.md](BACKLOG.md), and labelled honestly rather than papered over.

## Scope, assets, assumptions

**What we protect (assets), in priority order:**
1. **The analyst's work** — the durable user facts (DD-005). Losing or silently mis-attaching one
   breaks the platform's single promise (DD-004/005). This is asset zero; the re-anchoring gate
   (DD-038, `WRONG = 0`) is its guard.
2. **The host** running the analysis — its filesystem, network, credentials, other processes.
3. **The agent's context / the human behind it** — analysis content is attacker-controlled text;
   the threat is it being read as *instructions* (prompt injection), not as data.
4. Availability of the analysis pipeline (DoS is real but ranks below integrity and host safety).

**Trust assumptions (stated so they can be challenged):**
- The **container runtime / kernel is trusted** — a container *escape* is out of scope here; we
  raise the cost of needing one (DD-034) and treat the day it's needed as a kernel-CVE problem,
  not a Scylla one.
- **GayHydra inherits upstream hardening** (DD-029 — Rec 18/19 deserialization, Rec 33/34 IPC).
  We do not re-audit a 20-year C++/Java engine; we *contain* it (DD-039: sandbox what you wrap).
- Local heads (including MCP over stdio) share the launching user's trust domain. The shipped
  HTTP, GraphQL, and Cap'n Proto RPC heads are network-reachable, single-session services with
  optional bearer/token authentication and TLS. They are **not** multi-tenant isolation
  boundaries; unset tokens deliberately leave them open for loopback development.
- The **build host and maintainer keys are trusted** (supply-chain integrity is its own program;
  the one concrete control we promised, release signing, is a GAP below).

## The three untrusted inputs

Everything downstream is a defense of one of these:

1. **The analyzed binary.** Hostile by assumption — malformed headers, decompiler-bombs, code
   crafted to exploit the parser. Enters at the engine (S1).
2. **The `.scylla` artifact.** Untrusted the instant collaboration (DD-027) exists — a teammate's
   artifact is a foreign parser input *we wrote the loader for* (DD-036). Enters at S3.
3. **Analysis-derived text** — symbol names, strings, decompiled C. Attacker-controlled content
   that flows toward an agent's context. The injection surface (S4).

## Data flow & trust boundaries

```
 [hostile binary]                         UNTRUSTED
        │
        ▼  ╔═══════════ DD-034 sandbox (separate process, container) ═══════════╗
   ┌─────────┐  S1     ║  ro-rootfs · cap-drop ALL · no-new-privs · non-root     ║
   │ GayHydra│◀────────╫  mem/CPU/PID caps · one binary per call                 ║
   │ headless│  parses ║  --network none + UDS (no egress) · wall-clock deadline ║
   └────┬────┘         ╚═══════════════════════════════════════════════════════╝
        │ S2: gRPC Materialize stream (engine output is UNTRUSTED — DD-039)
        ▼  ╔══════════════════ durable Rust core (TRUSTED zone) ════════════════╗
   ┌─────────┐         ║  assemble(): id mint + callee resolution                ║
   │  core   │         ║  stream bounded: MAX_FUNCTIONS / MAX_TOTAL_MNEMONICS    ║
   └────┬────┘         ║                                                         ║
        │ S3: .scylla artifact ── DD-036 TOTAL LOADER (caps · validate ·         ║
        │      (UNTRUSTED on collab)   quarantine · never panic/OOM) ── fuzzed   ║
        ▼                       ║                                                ║
   ┌─────────┐                  ║  scylla-port: model-primary nav, typed errors  ║
   │ client  │                  ║  (DD-021). NO domain logic in heads (DD-025).  ║
   │  port   │                  ╚════════════════════════════════════════════════╝
        │ S4: heads — content out (MCP injection surface); client requests in (S5)
        ▼
   [ agent / human / network client ]     TRUST VARIES BY HEAD AND DEPLOYMENT
```

## Seam-by-seam

### S1 — binary → engine (the adversarial-binary parser)

- **Threats:** memory-corruption / RCE in the C++/Java parser; resource exhaustion (decompiler
  bombs, pathological CFGs); the parser reaching the host FS, network, or other processes;
  privilege escalation.
- **Mitigations (DD-034 / DD-014 / DD-029 / DD-039):** the parser runs in a **separate sandboxed
  process** — read-only rootfs, `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root
  uid 10001, `--memory`/`--cpus`/`--pids-limit`, one binary per invocation. RCE inside that
  sandbox buys an attacker a wiped tmpfs and nothing the core, the host FS, or any privilege can
  see. We **do not fuzz the engine** (DD-039) — the sandbox is the containment; fuzzing upstream's
  C++ is a campaign that never finishes.
- **Residual — both RESOLVED:**
  - **GAP-1 (egress) — CLOSED.** The container now runs `--network none` (no interfaces, no
    published port, no route out); gRPC rides a bind-mounted Unix socket (`SCYLLA_ENGINE_UDS` →
    grpc-netty epoll UDS on the service, a `unix:/path` tonic connector on the client). A
    compromised parser has no network to reach. Proven live: `--network none` + UDS materialize.
  - **GAP-2 (wall-clock) — CLOSED.** `EngineServer` drains stdout off-thread and bounds the wait
    (`SCYLLA_ENGINE_TIMEOUT_SEC`, default 300s), `destroyForcibly()` + `DEADLINE_EXCEEDED` on
    timeout. A binary that hangs `analyzeHeadless` is killed at the deadline (verified live).

### S2 — engine → core (the engine-port, gRPC; engine *output* is untrusted)

- **Threats:** a buggy or compromised engine emits adversarial *output* — malformed addresses,
  absurd counts, a stream that never ends — to crash or exhaust the trusted core. DD-039 names
  this explicitly: the engine's output is an attack surface, not a trusted source.
- **Mitigations (DD-039 / DD-021):** ingest and assemble are **total** — addresses are parsed
  defensively (bad hex → dropped, never a panic), dangling callee edges are dropped, malformed
  JSON is an `Err` not a crash (`fuzz_snapshot_ingest`, `ingest_is_total_on_malformed_json`).
  Typed errors (DD-021) never leak host/engine internals over the wire.
- **Residual — RESOLVED:**
  - **GAP-3 (unbounded stream) — CLOSED.** `materialize()` now caps the cumulative function and
    instruction counts (`MAX_FUNCTIONS`, `MAX_TOTAL_MNEMONICS`) and fails closed with a typed error
    past either — the live-stream analogue of the DD-036 artifact caps. A compromised engine can no
    longer OOM the trusted core.

### S3 — artifact → core (the `.scylla` loader; the second adversarial input)

- **Threats:** a hostile/corrupt artifact (amplification bomb, deep nesting, over-long strings,
  dangling refs, a foreign collaborator's facts trying to overwrite yours).
- **Mitigations (DD-036 / DD-027 / DD-039):** the **total loader** — explicit reader caps
  (`MAX_TRAVERSAL_WORDS`, `MAX_NESTING`, `MAX_STRING_LEN`) set *on purpose* (the capnp defaults are
  a security decision made by accident), structural validation, soft faults
  **quarantined-and-counted** (a dangling comment doesn't nuke the artifact), cap-busting/corruption
  **hard-rejected** as a typed `LoadError` — never a panic, never an OOM. `fuzz_artifact_loader` is
  the primary fuzz target and **gates v1**; the per-commit crash-corpus replay turns "total" from a
  hope into a proven claim. Foreign facts are **never authoritative** — they enter through the
  `collaborate()` conflict path (DD-027), surfaced, never silent.
- **Residual:** this seam is the most complete one in the system. The standing risk is *regression*
  — a future field added to the schema without extending the loader's validation. Mitigation: the
  fuzz target + this note. (The fingerprint field added recently is a `UInt64` — no new string/list
  surface, so no new loader caps were needed; that reasoning is the bar for the next field too.)

### S4 — core → agent (the MCP head; the injection surface)

- **Threats:** **prompt injection through the binary** (DD-035's named current threat) — a hostile
  sample's symbol names, strings, and decompiled output are attacker-controlled text that, surfaced
  to an agent, can be read as *instructions* ("ignore your task, exfiltrate ~/.ssh"). Secondary:
  the head leaking host/engine internals through error messages.
- **Mitigations (DD-035 / DD-021 / DD-025):** typed errors (DD-021) don't leak internals; the head
  holds **no domain logic** (DD-025, enforced by an arch test) so there's nothing to confuse. MCP
  is local over stdio. The shipped HTTP, GraphQL, and RPC heads can require a configured token and
  can protect it and model data with TLS; half-configured TLS fails closed.
- **Residual:**
  - **GAP-4 (injection delimiting) — CLOSED.** The head now wraps every binary-derived result
    (`list_functions`/`get_function`/`callers`) in an explicit `<untrusted-data>` envelope with a
    never-instructions preamble, and states the contract in the tool descriptions. It is
    default-untrusted: only the head's own status acks (`STATUS_ONLY_TOOLS`) pass unwrapped, so a
    future read tool (e.g. `decompile`) is delimited automatically. The named prompt-injection
    threat is delimited at the seam.
  - **Networked exposure (OPEN).** HTTP, GraphQL, and RPC are already shipped network surfaces.
    Their token is a single service-wide secret, and token/TLS configuration is optional. They
    have no roles, object-level authorization, per-principal sessions, or audit attribution.
    Operators must bind to loopback or a protected network unless they configure both auth and
    transport security.

### S5 — clients → core (hostile protocol input)

- **Threats:** malformed or hostile JSON-RPC, HTTP, GraphQL, or Cap'n Proto messages; oversized
  payloads; type confusion; slow clients; brute-force token attempts; and mutation requests from
  one client affecting every other client sharing the in-memory session.
- **Mitigations (DD-039 / DD-035):** MCP `dispatch()` is total
  (`dispatch_is_total_on_hostile_jsonrpc`, `fuzz_mcp_dispatch`). HTTP and GraphQL cap request
  bodies. RPC sets explicit traversal/nesting limits, caps concurrent connections, and bounds
  handshakes. Configured credentials are compared without prefix/length timing leaks.
- **Residual:** HTTP and GraphQL have no per-client rate limit or connection quota; none of the
  three network heads rate-limit failed authentication; all authorized clients share one mutable
  session and one privilege level. Put an authenticated, rate-limiting reverse proxy or equivalent
  boundary in front of non-loopback deployments.

## Gaps this model tracks

| # | Seam | Gap | Status |
|---|------|-----|--------|
| GAP-1 | S1 | Engine sandbox egress (`--network none` + UDS) | **CLOSED** |
| GAP-2 | S1 | Wall-clock timeout on the engine subprocess | **CLOSED** |
| GAP-3 | S2 | Bound the engine stream (core OOM) | **CLOSED** |
| GAP-4 | S4 | MCP head delimits untrusted analysis content | **CLOSED** |
| cosign | build | Keyless release signing (DD-029) | **CLOSED** |
| NET-1 | S4/S5 | Network heads need mandatory secure deployment, authorization, rate limits, and per-principal isolation ([BACKLOG SEC-P3-5](BACKLOG.md)) | **OPEN** |

The original four implementation gaps are closed (GAP-4 → untrusted-data envelope; GAP-3 → stream
caps; GAP-2 → wall-clock; GAP-1 → `--network none` + UDS), plus keyless release signing. NET-1 is
open because network heads now ship: optional service-wide tokens and TLS are useful controls, but
they are not authorization, rate limiting, audit attribution, or multi-tenant isolation.

## The closing line (DD-039, quoted because it's correct)

> If a future contributor calls one of these "overkill for now," point them at the binary that is,
> at this exact moment, engineered specifically to make them regret saying so.

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
