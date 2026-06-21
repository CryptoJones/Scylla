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
- The **user and the agent they launch share a trust domain** in v1 (DD-035) — stdio, local,
  single-user. Networked/multi-tenant exposure is explicitly a later surface, called out below.
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
        │ S4: MCP head — content out (injection surface), JSON-RPC in (S5)
        ▼
   [ agent / human ]                      SEMI-TRUSTED (v1 local; networked = later)
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
  holds **no domain logic** (DD-025, enforced by an arch test) so there's nothing to confuse; v1 is
  local single-user (DD-035) so the network attack surface is nil.
- **Residual:**
  - **GAP-4 (injection delimiting) — CLOSED.** The head now wraps every binary-derived result
    (`list_functions`/`get_function`/`callers`) in an explicit `<untrusted-data>` envelope with a
    never-instructions preamble, and states the contract in the tool descriptions. It is
    default-untrusted: only the head's own status acks (`STATUS_ONLY_TOOLS`) pass unwrapped, so a
    future read tool (e.g. `decompile`) is delimited automatically. The named prompt-injection
    threat is delimited at the seam.
  - **Networked exposure (tracked, not yet due).** When a future head is networked/multi-tenant
    (DD-035), it needs authn/authz, rate-limiting, and per-principal isolation. The identity seam
    (DD-035, `Option<Principal>`) is already threaded so that arrives without a core rewrite — but
    none of the auth machinery exists yet, on purpose (no users to knock on the door).

### S5 — agent → core (MCP head input; hostile JSON-RPC)

- **Threats:** malformed / hostile JSON-RPC driving the head — oversized payloads, garbage,
  type-confusion, calls designed to panic the server.
- **Mitigations (DD-039):** `dispatch()` is **total** (`dispatch_is_total_on_hostile_jsonrpc`,
  `fuzz_mcp_dispatch`: never panics, always returns well-formed JSON-RPC, even on garbage). This
  seam is well-defended.
- **Residual:** no resource/rate limiting on request volume — irrelevant under v1 local trust,
  required when networked (folded into the networked-exposure item above).

## Gaps this model found (all now closed → BACKLOG)

| # | Seam | Gap | Status |
|---|------|-----|--------|
| GAP-1 | S1 | Engine sandbox egress (`--network none` + UDS) | **CLOSED** |
| GAP-2 | S1 | Wall-clock timeout on the engine subprocess | **CLOSED** |
| GAP-3 | S2 | Bound the engine stream (core OOM) | **CLOSED** |
| GAP-4 | S4 | MCP head delimits untrusted analysis content | **CLOSED** |
| cosign | build | Keyless release signing (DD-029) | **CLOSED** |
| — | S4 | Networked head: authn/authz/rate-limit (DD-035) | deferred — no networked head yet |

Every gap this pass surfaced has since been closed (GAP-4 → untrusted-data envelope; GAP-3 → stream
caps; GAP-2 → wall-clock; GAP-1 → `--network none` + UDS), plus keyless release signing. The one
open item is networked-head auth, deliberately deferred until there is a networked head to attack —
and the identity seam (DD-035) is already in place so it lands without a core rewrite.

## The closing line (DD-039, quoted because it's correct)

> If a future contributor calls one of these "overkill for now," point them at the binary that is,
> at this exact moment, engineered specifically to make them regret saying so.

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
