# Scylla — Code Review Recommendations

- **Date:** 2026-07-01
- **Commit reviewed:** `main` @ `4e02cdb` (clean tree, up to date with `origin/main`)
- **Scope:** the 15-crate Rust workspace (`crates/*`, ~11.5 KLOC), the Java `engine-service`
  (`EngineServer.java`, ~613 LOC), and workspace/CI/build hygiene.
- **Method:** six parallel per-crate reviewers (read-only) fanned out across crate clusters, plus a
  workspace-level hygiene pass. Every finding is anchored to `file:line`. The highest-severity claims
  (both `scylla-merge` P0s, the `scylla-rpc` server-kill, the `scylla-mcp` envelope defeat, the
  `scylla-http` auth/body/TLS trio, and the `scylla-ingest`/`scylla-schema` P1s) were re-read and
  **verified directly against the source**; the remainder are reviewer-reported and consistent with
  the verified track record. Items flagged **[verified]** were personally confirmed line-by-line.

## Priority legend

| Pri | Meaning |
|-----|---------|
| **P0** | Critical — a correctness contract (`WRONG=0`) or security boundary is actually breached. Fix before the next release. |
| **P1** | High — a real bug, DoS, or auth/crypto weakness reachable from untrusted input. |
| **P2** | Medium — robustness, missing tests on a load-bearing invariant, complexity/DoS on attacker-sized input, maintainability. |
| **P3** | Low — nits, dead code, stale/incorrect comments, style, micro-optimizations. |

**Deployment caveat on severity:** priorities assume the worst-case posture the code supports —
a network-exposed head (`0.0.0.0`, token unset) fed a *hostile* artifact. On a pure-loopback,
single-analyst dev setup several P1 web/RPC items are materially lower risk. They are still listed at
their worst-case severity because the heads advertise `SCYLLA_*_TOKEN` + TLS, i.e. they are *designed*
to be exposed.

## Summary counts

| Pri | Count |
|-----|------:|
| P0  | 5 |
| P1  | 16 |
| P2  | 24 |
| P3  | 48 |

---

## Cross-cutting root causes (fix the root, close many findings)

1. **Non-constant-time bearer-token comparison** — the same `presented == token` byte-compare (leaks
   length + prefix via timing) appears in **three** network heads: `scylla-http`, `scylla-graphql`,
   `scylla-rpc`. One shared constant-time compare helper (`subtle::ConstantTimeEq` over equal-length
   digests) fixes all three. → HTTP-P1-1, RPC-P1-1.
2. **The `<untrusted-data>` envelope is defeatable** — `wrap_untrusted` interpolates a `serde_json`
   payload (which does **not** escape `<`, `>`, `/`) between literal `</untrusted-data>` tags in
   **both** `scylla-mcp` and `scylla-lsp`. A hostile function name containing the closing sentinel
   breaks out of the envelope. This is the DD-035 prompt-injection contract, and it does not hold.
   → MCP-P0-1, LSP-P0-1.
3. **Address-keyed id minting collides** — `scylla-ingest` and `scylla-engine::assemble` both key the
   `StableId` map by entry address; duplicate or unparseable addresses collapse two functions onto one
   id, violating DD-004 identity uniqueness. → INGEST-P1-1, ENGINE-P2-1.
4. **One-sided uniqueness in the merge/collaborate paths** — `reanchor_facts` and `collaborate` enforce
   uniqueness/reciprocity on only *one* side, while the diff path (`diff_programs`) already does the
   correct both-sided, margin-gated version. Porting that discipline over closes all four merge
   correctness items. → MERGE-P0-1, MERGE-P0-2, MERGE-P1-1, MERGE-P1-2.
5. **Unbounded reads from untrusted input** — every network/stdio boundary reads without a size cap:
   HTTP/GraphQL body, RPC wire (reader limits at `Default`), MCP stdin line, LSP `Content-Length` and
   header line, engine stream (item-counted, not byte-counted). A shared "max bytes" posture is missing.
6. **No mechanical enforcement of the no-panic / no-unwrap discipline** — for a project whose contracts
   are "the loader never panics" and "`WRONG=0`", there is **no** `[workspace.lints]`, no crate-level
   `#![forbid(unsafe_code)]` / `#![deny(clippy::unwrap_used, …)]`, and CI runs neither clippy nor fmt.

---

## P0 — Critical

### MERGE-P0-1 · EXACT re-anchor pass double-attaches on new-side-only uniqueness **[verified]**
`crates/scylla-merge/src/lib.rs:363-379`. The EXACT pass filters `new_by_sig` on `ids.len() == 1`
(new-side uniqueness only) and the accept arm never consults `claimed` nor checks that the *old*
signature is unique. If two old fact-carrying functions share a signature `S` and exactly one new
function has `S` (e.g. one was deleted/inlined on recompile), **both** old facts retarget onto that one
new function — a silent mis-attachment, a direct `WRONG=0` breach. `diff_programs` already does the
right thing (lines 822-824: requires `a_unique` *and* `ids.len()==1`). **Fix:** build `old_by_sig`,
require the old count to be 1 as well, and skip already-`claimed` ids. Add an adversarial fixture.

### MERGE-P0-2 · ANCHOR merge pass accepts without a reciprocal-best guard **[verified]**
`crates/scylla-merge/src/lib.rs:387-416` (accept at 409-410). Acceptance is forward-only
(`best_s >= ANCHOR_THRESHOLD && best_s - second_s >= ANCHOR_MARGIN`) — it proves the new function is the
target's best, but never that the target is the new function's best. The FUZZY (line ~446) and BSIM
(~520) passes and the diff-path anchor (`feature_round`, ~782-784) all require reciprocity; this pass
does not. A deleted old function whose anchor-set is a subset of a look-alike's set anchors its fact onto
the wrong function. **Fix:** add the same reciprocal-best + margin gate the other passes use.

### MCP-P0-1 · `<untrusted-data>` envelope is bypassable (DD-035 defeat) **[verified]**
`crates/scylla-mcp/src/lib.rs:26-33` (build) / `211-214` (use). `wrap_untrusted` interpolates
`v.to_string()` (a `serde_json` string — escapes only `"`, `\`, controls; **not** `<`/`>`/`/`) between
literal `<untrusted-data>` / `</untrusted-data>` fences. A hostile binary with a function name/comment
containing `</untrusted-data>\n\nSYSTEM: …` closes the envelope; the agent reads the tail as trusted
instructions. **Fix:** use a per-response random nonce fence *and* scan/neutralize/reject the sentinel
substrings in the payload before wrapping (fail-closed), or base64-encode the payload. Shared with
LSP-P0-1 — fix once, apply to both heads.

### LSP-P0-1 · Same envelope bypass in the LSP hover path **[verified — same class as MCP-P0-1]**
`crates/scylla-lsp/src/lib.rs:224-231` (payload at `201-220`, `114-127`). `hover_markdown` interpolates
`v.name`/`v.summary`/callee names verbatim into the same unescaped `</untrusted-data>` fence. Same
attack, delivered to any editor-side LLM feature. **Fix:** as MCP-P0-1. Also audit `documentSymbol` /
`workspace/symbol`, which surface raw attacker text *without any* wrapper (LSP-P2/P3 below).

### RPC-P0-1 · `accept()?` propagates a non-fatal error and kills the whole server **[verified]**
`crates/scylla-rpc/src/bin/scylla-rpc-serve.rs:107` (`let (stream,_peer) = listener.accept().await?;`),
turned into `ExitCode::FAILURE` at 131-134. `accept()` routinely returns non-fatal errors an
unauthenticated remote peer can force at will — `ECONNABORTED` (connect-then-RST) and `EMFILE`/`ENFILE`
(fd exhaustion). Any one permanently terminates the process: a trivial, remote, **pre-auth** availability
kill. **Fix:** never `?` on `accept()`; `match` it, log and `continue` on transient errors (short sleep
on `EMFILE`/`ENFILE` to avoid a busy-spin), break only on a genuinely fatal listener error.

---

## P1 — High

### HTTP-P1-1 · Non-constant-time bearer-token comparison (http + graphql) **[verified: http]**
`scylla-http/src/main.rs:152-155`, `scylla-graphql/src/main.rs:179-182`. `h.value.as_str() == want`
short-circuits on length then first differing byte — a timing oracle recovering the token
byte-by-byte (practical on the LAN/loopback deployment). **Fix:** constant-time compare (see
cross-cutting #1).

### RPC-P1-1 · Non-constant-time token compare (rpc)
`crates/scylla-rpc/src/lib.rs:93` (`presented != t.as_str()`). Same oracle, amplified by RPC-P2-2
(unlimited, unlogged reconnects). `subtle` is already in the tree transitively. **Fix:** as above.

### HTTP-P1-2 · Unbounded request body → memory-exhaustion DoS (http + graphql) **[verified: http]**
`scylla-http/src/main.rs:182-183` and `332-333`; `scylla-graphql/src/main.rs:147-148`. `read_to_end`
with no cap; `tiny_http` sets no default limit. Unauthenticated when the token is unset (the default);
the `diff` paths additionally hand attacker bytes to `Session::from_artifact`. Effectively P0 once bound
off-loopback. **Fix:** `req.as_reader().take(MAX_BODY)`, reject oversized `Content-Length` with `413`.

### GQL-P1-3 · GraphQL alias amplification on expensive resolvers
`scylla-graphql/src/main.rs:158` runs `execute_sync` with no complexity/cost limit. `export`
(`schema.rs:325-328`) base64s the whole model; `diff` (`schema.rs:270-274`) loads a full `Session` per
field. One aliased request (`{a:export b:export …}` / repeated `diff`) multiplies CPU/response size.
**Fix:** a juniper look-ahead complexity guard capping aliased `export`/`diff`, and/or response-size +
argument-length caps.

### RPC-P1-2 · TLS handshake has no timeout → connection-cap bypass / slow-loris **[verified]**
`scylla-rpc/src/bin/scylla-rpc-serve.rs:113` increments the slot, `121` does `a.accept(stream).await`
with no timeout; the `SCYLLA_RPC_HANDSHAKE_SEC` window only applies *inside* `serve_with_timeout` (122),
i.e. after TLS. A peer that completes TCP then stalls the TLS handshake holds a counted slot forever;
`SCYLLA_RPC_MAX_CONN` such connections exhaust the cap. The plaintext path is protected; the TLS path
is not. **Fix:** `tokio::time::timeout(handshake, a.accept(stream))`.

### SCHEMA-P1-1 · Total loader truncates only *some* untrusted strings **[verified]**
`crates/scylla-schema/src/lib.rs:300-337`. The loop bounds `func.name`, `func.mnemonics`,
`string_refs`/`imports`/`callee_names`, and fact-kind strings — but **not** `func.trigrams` (the same
untrusted engine data as `mnemonics`), `edge_provenance[].producer`, `fact.provenance.producer`,
`fact.author`, or `prog.name`/`prog.language` (copied whole in `from_bytes`). A 400 MiB `program.name`
loads intact, `truncated_strings` stays 0, and `report.clean()` returns `true` — the report lies.
**Fix:** truncate every remaining untrusted string in the load loop and count each in the report.

### SCHEMA-P1-2 · 512 MiB traversal limit + copying `read_message` is the dominant OOM surface
`crates/scylla-schema/src/lib.rs:231,239,115`. `MAX_TRAVERSAL_WORDS = 512 MiB` (8× the capnp default),
and `read_message` allocates owned segment storage up to that limit *before* decode, duplicating the
input buffer (peak ≈ 1–1.5 GiB from one file). A ~20-byte artifact declaring a ~511 MiB segment drives a
near-512 MiB allocation. Bounded, but not "never OOMs" on the memory-constrained target. **Fix:**
`read_message_from_flat_slice` (zero-copy borrow) and lower `MAX_TRAVERSAL_WORDS` to the smallest value
real artifacts need.

### SCHEMA-P1-3 · Loader never validates `edge_provenance` targets
`crates/scylla-schema/src/lib.rs:300-325`. `load` drops dangling `callees` and `facts` but never filters
`func.edge_provenance` against `valid_ids` or the surviving `callees`. A hostile artifact keeps
provenance for a nonexistent/quarantined edge — an uncounted soft fault. **Fix:**
`func.edge_provenance.retain(|e| func.callees.contains(&e.target))`, counted in the report.

### INGEST-P1-1 · Stable-id collision on duplicate/unparseable entry addresses (DD-004) **[verified]**
`crates/scylla-ingest/src/lib.rs:50-52` (`parse_addr` → `unwrap_or(0)`), `61-64` (id map keyed by
address), `77` (`id: id_of[&addr]`). Two functions with the same parsed entry — or any two unparseable
entries, both → `0` — collide; the second `insert` overwrites, so both get the same `StableId`,
corrupting facts/`callers`/diff/merge. **Fix:** mint per function-index; make `parse_addr` return
`Option`; reject/report duplicate entries. (Lower blast radius than a network path — ingest is the
offline dev/corpus producer — but the test file itself warns a buggy engine "could emit anything.")

### ENGINE-P1-1 · `destroyForcibly()` kills the wrapper, not the Ghidra JVM (GAP-2 bypass)
`engine-service/.../EngineServer.java:405-411` (also `WarmWorker.close()` 231). `analyzeHeadless` forks a
grandchild JVM; `destroyForcibly()` kills only the launcher script, orphaning the real analysis JVM which
keeps burning CPU/RAM past the deadline — the wall-clock guarantee is not delivered. **Fix:**
`p.descendants().forEach(ProcessHandle::destroyForcibly)` then kill the root (or use a process group).

### ENGINE-P1-2 · Default 4 MB gRPC inbound limit contradicts the 200 MB-firmware design goal
`engine-service/.../EngineServer.java:588-593`, `605-606` (neither sets `maxInboundMessageSize`).
`job.rs:6` justifies the async handle by "a 200 MB firmware analysis," but `MaterializeRequest.binary`
carries the whole binary and gRPC-Java caps inbound at 4 MiB by default → any binary > 4 MB is rejected
with `RESOURCE_EXHAUSTED` before analysis. **Fix:** set a deliberate `.maxInboundMessageSize(...)` on
both server builders and matching tonic client decode limits.

### LSP-P1-1 · Unbounded `Content-Length` → allocation DoS/abort
`crates/scylla-lsp/src/main.rs:79-89`. `content_length` is an unbounded `usize` from the header;
`vec![0u8; content_length]` attempts a multi-TB allocation *before* reading a byte
(`Content-Length: 99999999999999`). A negative value → `parse` fails → `unwrap_or(0)` silently treats it
as empty. **Fix:** reject `content_length > ~32 MiB` and close; distinguish a parse failure from 0.

### MERGE-P1-1 · `best_old_match` resolves reciprocity ties to first-seen; comment is false **[verified]**
`crates/scylla-merge/src/lib.rs:101-112` (consumed at ~446, ~520). Strict `>` keeps the first old on a
tie, so if the fact-carrying old is first in `old.functions`, `best_old_match(nf) == oldf` and
reciprocity *passes* despite a genuine tie — output also becomes ordering-sensitive. The doc (99-100)
claims it "fails closed on ties"; it does not. **Fix:** add a runner-up margin (return `None` unless the
top strictly and clearly beats second), like `best_unique`; correct the comment.

### MERGE-P1-2 · `collaborate` re-anchors on base-side uniqueness only
`crates/scylla-merge/src/lib.rs:949-954`. Same class as MERGE-P0-1: two incoming functions sharing a
signature both collapse onto one base function; the incoming-side signature is never required unique.
**Fix:** also require incoming-side uniqueness (or flag when it isn't).

### MERGE-P1-3 · Merge-path `propagate_match` lacks the both-sides-unique/reciprocal check
`crates/scylla-merge/src/lib.rs:228-260`. The margin is computed over candidate (new-side) scores only;
two old leftovers with the same matched neighbourhood can each clear `PROP_MARGIN`, and first-processed
claims the candidate. The diff path (`propagate_round`, 724-735) uses `group_unique` on both sides plus a
reciprocity check; the merge path does not. **Fix:** adopt the diff path's both-sides-unique keying.

---

## P2 — Medium

### Security / robustness
- **HTTP-P2-1 / GQL · Silent plaintext fallback on partial TLS config** **[verified: http]** —
  `scylla-http/src/main.rs:79-95`, `scylla-graphql/src/main.rs:63-79`. Setting only one of
  `_TLS_CERT`/`_TLS_KEY` silently serves cleartext (token + model in the clear). Fail closed: if either
  is present, require both.
- **HTTP-P2-2 / GQL · CSRF / DNS-rebinding on state-changing POST** — body parsed as JSON regardless of
  `Content-Type` (`scylla-http/src/main.rs:189`); no `Origin`/`Host` check. A web page can POST
  `…/rename` to a victim's loopback session. Require `Content-Type: application/json` and/or validate
  `Host`/`Origin` for mutations.
- **HTTP-P2-3 / GQL · Single-threaded body read → slowloris** — `scylla-http/src/main.rs:124`,
  `scylla-graphql/src/main.rs:111`. One dribbling client stalls all clients. Add read/idle timeouts or a
  worker pool.
- **HTTP-P2-4 / GQL · No panic boundary** — no `catch_unwind` around dispatch; the first panic (e.g. a
  crafted-but-loadable `diff` artifact, or a `.lock().expect()` in `schema.rs`) aborts the process for
  everyone. Wrap per-request handling; return `500`.
- **HTTP-P2-5 / GQL · No pagination** — `{functions}` / `search` / `/api/functions` return every function
  (`schema.rs:209,217`, `main.rs:269`); a large binary yields an unbounded response. Add a server-capped
  page size.
- **RPC-P2-1 · VatNetwork reader limits at `Default` on the network crate** — `scylla-rpc/src/lib.rs:384,
  405,440`. The sister crate sets explicit caps "on purpose (a security decision)"
  (`scylla-schema/src/lib.rs:225`); the network-facing crate inherits the library default. Set an
  explicit, tighter `ReaderOptions`.
- **RPC-P2-2 · No auth-failure rate-limit/lockout/logging; peer discarded** —
  `scylla-rpc-serve.rs:107` drops `_peer`; `lib.rs:92-98` allows unlimited, invisible token guessing.
  Log peers + failures; add backoff/lockout. Turns RPC-P1-1 from theoretical to practical.
- **RPC-P2-3 · Heavy synchronous port calls block the single-thread executor** — `lib.rs:196-199` (`diff`
  parses + O(n·m) diffs synchronously); one pathological artifact freezes the whole service. Bound the
  `diff` artifact size; yield/budget.
- **RPC-P2-4 · Shared mutable session, no read-only vs read-write cap** — `lib.rs:55-57,322-365`. In OPEN
  mode any unauthenticated client can mutate the shared model all others read/export. Add a read-only
  capability or per-client annotation isolation.
- **RPC-P2-5 · No idle/session timeout after auth** — `lib.rs:395-430`. The handshake watchdog bounds only
  the pre-auth window; authenticated-idle connections hold slots forever. Add an idle/absolute timeout.
- **MCP-P2 · Unbounded stdin line length** — `scylla-mcp/src/main.rs:25` (`.lines()` uncapped) → OOM on a
  giant newline-less line. Use a bounded reader.
- **MCP-P2 · One bad UTF-8 byte kills the server** — `scylla-mcp/src/main.rs:26-29` `break`s on a decode
  error (while a JSON parse error two lines down only `continue`s). Skip the bad line; break only on EOF.
- **MCP-P2 · Unrestricted filesystem read/write by agent-supplied path** — `export` writes
  (`lib.rs:164-172`), `diff`/`merge` read (`132-138,178-185`) arbitrary paths → arbitrary file overwrite
  with the user's privileges (chains with MCP-P0-1). Confine to a working dir (reject absolute/`..`).
- **MCP-P2 · JSON-RPC batch requests silently dropped** — `main.rs:33-40`. An array batch has no `id`, is
  treated as a notification, and gets no reply → client hangs. Dispatch elements or return `-32600`.
- **WASM-P2 · `(ptr << 32) | len` corrupts the pointer on 64-bit** — `scylla-wasm/src/lib.rs:48-53`. Sound
  only on wasm32, but the crate is `cdylib`+`rlib` and links natively (64-bit tests exist); native use
  frees an invalid pointer (UB). Add `#[cfg(target_pointer_width="32")]`/`compile_error!` or a
  `debug_assert!`.
- **MODEL-P2 · `IdMinter` derives `Default` (0-based), inconsistent with `new()` (1-based); mints
  `StableId(0)`** — `scylla-model/src/lib.rs:21-35`. `StableId(0)` is indistinguishable from a capnp unset
  field. Hand-write `Default` to call `new()`; reserve `StableId(0)` as invalid.
- **SCHEMA-P2 · Loader does not reject/dedup duplicate stable ids** — `scylla-schema/src/lib.rs:298-299`.
  Two functions sharing an id both pass; `.find(|f| f.id==id)` silently picks the first. Detect duplicates
  on load and drop-with-count or reject.
- **PORT-P2 · `Session::from_artifact` silently discards the `LoadReport`** —
  `scylla-port/src/lib.rs:130-135`. The whole point of the report (dropped/truncated data) is thrown away,
  so a head sees a quarantined artifact as clean. Return or store the report.
- **PORT-P2 · `functions()` / `search()` are O(n²)** — `scylla-port/src/lib.rs:202-207,213-222`; `view`
  always computes `callers` (159-166) even at `Intent`. Precompute a caller index once; filter names
  before building full views.
- **INGEST-P2 · Unresolved/garbage callees silently dropped or mis-resolved** —
  `scylla-ingest/src/lib.rs:70-74`. A callee that parses to `0` resolves to whatever collapsed to key 0
  (wrong edge); a non-match is dropped with no diagnostic. Fix with INGEST-P1-1's `Option` + counts.
- **ENGINE-P2-1 · `assemble` mints ids keyed by entry address → duplicate `StableId`s** —
  `scylla-engine/src/lib.rs:60-76`. Same defect as INGEST-P1-1 on the primary (engine) producer path;
  the untrusted engine can trivially trigger it. Detect duplicate `entry` and fail closed; add a test.
- **ENGINE-P2-2 · Stream caps count items, not bytes, and ignore most fields** —
  `scylla-engine/src/lib.rs:89-106,163-168`. `MAX_FUNCTIONS=1M`, `total_mnemonics` counts strings not
  bytes; `string_refs`/`imports`/`callee_names`/`bsim_vector`/`callees` are uncounted. A malicious engine
  streams ~4 TB without tripping a cap. Accumulate a byte budget across all retained fields.
- **ENGINE-P2-3 · Cold `materialize` leaks the temp project dir every request** —
  `EngineServer.java:372-375` create, `428-431` finally deletes `bin`/`out` but never the `scylla-proj*`
  dir → inode/disk exhaustion over time. Recursively delete `proj` in `finally`. (`WarmEngine`'s
  `scylla-warm-classes` dir 252 leaks once per process — lower.)
- **ENGINE-P2-4 · Cold subprocess path has no concurrency cap** — `EngineServer.java:345-432`. Unlike the
  pool-bounded warm path, the default cold path forks one full Ghidra JVM per concurrent request → host
  exhaustion under a burst. Gate behind a memory-sized `Semaphore`.
- **LSP-P2 · Unbounded blocking `read_line` header** — `scylla-lsp/src/main.rs:70-83`. Newline-less
  megabytes → unbounded `String` + blocks the single thread. Cap header-line/total-header bytes.
- **LSP-P2 · Malformed JSON body swallowed, no `-32700`** — `scylla-lsp/src/main.rs:89`
  (`unwrap_or(Value::Null)`) → a request with an id gets no response and hangs. Emit `-32700`.
- **LSP-P2 · Positions use `chars().count()` but LSP is UTF-16** — `scylla-lsp/src/lib.rs:85-90` used at
  100,126,144,161,181-186. A supplementary-plane char under-counts; most damaging in `rename` (181) —
  the `WorkspaceEdit` range is short and leaves trailing chars. Use `encode_utf16().count()` or negotiate
  `positionEncoding="utf-8"`.
- **TUI-P2 · A panic in the event loop wedges the terminal** — `scylla-tui/src/main.rs:74-86`. Restoration
  is sequential code, not a guard; a panic unwinds past `disable_raw_mode()`/`LeaveAlternateScreen`,
  leaving the shell in raw mode on the alt screen (the comment claiming "always restore" is misleading).
  Install a terminal-restoring panic hook or an RAII drop guard.
- **MERGE-P2 · Soft-pass re-anchors don't downgrade fact confidence** — `scylla-merge/src/lib.rs:534`. A
  fuzzy/anchor/bsim carry preserves the original `Provenance` verbatim (reads as `confidence:100`) while
  `diff_programs` records a real `MatchInfo` confidence (592-597); a fuzzy-carried fact can then win a
  `collaborate` confidence resolution. Record a match-derived confidence on soft re-anchors.
- **MERGE-P2 · Missing adversarial `WRONG=0` fixtures** — no test constructs the exact/anchor/reciprocity
  collisions above; `reanchor_gate.rs` relies on collision-free snapshots. Add hand-built collision
  fixtures (like those at lines 1180+, 1329+).
- **MERGE-P2 · `cosine`/`bsim_similarity` assume dedup'd keys + finite weights** —
  `scylla-merge/src/lib.rs:50-69,268-294`. Duplicate keys make `na`/`nb` inconsistent (similarity can
  exceed 1.0); `f32::from_bits` yields `NaN`/`inf` for hostile bit patterns (fail-closed but undocumented).
  Re-validate / guard `w.is_finite()`.
- **MERGE-P2 · `collaborate` considers only the first base fact per `(target,kind)`** —
  `scylla-merge/src/lib.rs:960-963,998-1004`. Multiple same-kind facts on a target are permitted by the
  model but silently ignored. Document or handle.
- **MERGE-P2 · Quadratic, allocation-heavy matching is a DoS on attacker-sized programs** —
  anchor pass recomputes `anchor_set(nf)` per pair (400); `feature_round` allocates two `HashSet`s per
  pair per fixpoint round (858-863,772-786). ~O(N²·features). Precompute `anchor_set`/norms once per
  function.
- **CI/WORKSPACE-P2 · No lint enforcement** — no `[workspace.lints]`, no `#![forbid(unsafe_code)]` /
  `#![deny(clippy::unwrap_used,…)]`, no `clippy.toml`/`rustfmt.toml`; CI (`ci.yml`) runs only
  `cargo test` — no `cargo clippy -D warnings`, no `cargo fmt --check`, no `cargo audit`/`deny` for
  dependency CVEs & licenses. Add these; especially deny `unwrap_used`/`panic`/`indexing_slicing` on
  `scylla-schema`.
- **CI/WORKSPACE-P2 · Fuzz coverage lags the architecture** — three targets (`artifact_loader`,
  `mcp_dispatch`, `snapshot_ingest`) for nine heads; the RPC wire, HTTP/GraphQL body, and the hand-rolled
  LSP `Content-Length` parser are unfuzzed untrusted-input boundaries. Add targets.

---

## P3 — Low / nits

### scylla-http / scylla-graphql
- **HTTP-P3-1 · Empty token env var fails open** — `main.rs:72-74` / gql `58-60`: `SCYLLA_HTTP_TOKEN=""`
  → treated as unset → OPEN; a whitespace-only value becomes a real weak token. Warn/reject. **[verified]**
- **HTTP-P3-2 · Query string never percent-decoded** — `main.rs:167-171`; `?q=foo%20bar` reaches `search`
  literally, and `&`/`=` in a value can't be expressed. Use `form_urlencoded`. **[verified]**
- **HTTP-P3-3 · `display_name` miss handled inconsistently** — gql `schema.rs:264` `unwrap_or_default()`
  (empty string) vs http `main.rs:326` (`null`). Pick one wire shape.
- **HTTP-P3-4 · `callers` re-implements `parse_id` inline** — `main.rs:312-315` vs the shared `parse_id`
  (174). DRY.
- **GQL-P3-5 · Lossy `len() as i32` casts** — `schema.rs:204,238,309,313`. Counts wrap negative past
  `i32::MAX`; the crate already stringifies `u64` ids to avoid this — be consistent (`try_into`/clamp).
- **HTTP-P3-6 · Unknown `zoom` silently defaults to `DOMAIN`** — `main.rs:158-164`, gql
  `schema.rs:51-57`; `?zoom=detials` silently returns coarse data. Error or document.
- **HTTP-P3-7 · Error strings may leak internals** — `main.rs:192,344`, gql `main.rs:168` echo
  `PortError`/serde detail. Scrub any variant that can embed a filesystem path.
- **HTTP-P3-8 · Missing security headers** — no `X-Content-Type-Options: nosniff`; GraphiQL loads CDN
  assets with no SRI/CSP (gql `main.rs:129,193-199`).
- **GQL-P3-9 · Introspection always enabled** — `main.rs:158`; `tests/api.rs:79` pins it on. Add a prod
  off-switch for introspection + GraphiQL.
- **HTTP-P3-10 · `Header::from_bytes(...).unwrap()`** — `main.rs:137`, gql `186,195`. Constant inputs;
  prefer `.expect("static header is valid")`. **[verified: http]**
- **HTTP-P3-11 · `format!("Bearer {t}")` rebuilt per request** — `main.rs:152`, gql `179`. Reconstructs
  the secret + heap-allocates in the hot auth path; precompute once.
- **Missing tests** — no oversized-body / malformed-JSON / invalid-base64 / invalid-`Content-Type` tests;
  graphql has **no TLS test** despite advertising `_TLS_CERT/KEY`; graphql tests a no-bearer reject but
  not a *wrong*-bearer reject (http does).

### scylla-rpc
- **RPC-P3-1 · Client silently falls back to plaintext when `SCYLLA_RPC_TLS_CA` unset** —
  `scylla-rpc-connect.rs:63-96` sends the token in cleartext with no warning. Warn / add a require-TLS mode.
- **RPC-P3-2 · Connection-count decrement is not RAII-guarded** — `scylla-rpc-serve.rs:113-127`; a
  panic/early-return before line 127 leaks a slot. Use a `Drop` guard. **[verified]**
- **RPC-P3-3 · Public `serve_connection` has no handshake timeout** — `lib.rs:372-389`; a production
  embedder inherits the unbounded-idle problem. Document/fold in the timeout.
- **RPC-P3-4 · Invalid zoom byte coerced to Domain** — `lib.rs:39-45`. Reject out-of-range or document.
- **RPC-P3-5 · `addr`/`bb_count`/`size` `unwrap_or(0)` conflate 0 with absent** — `lib.rs:299-301`. Address
  `0` is legitimate; mark presence in the schema.
- **RPC-P3-6 · Unchecked `as u32`/`as u64` truncation on length fields** — `lib.rs:126,145,181,202,214,
  222,228,240,249,314`. Use checked conversions + explicit caps.
- **RPC-P3-7 · `from_artifact` error string reflected to the client** — `lib.rs:198`. Return a generic
  "invalid artifact"; log detail server-side.
- **RPC-P3-8 · `SCYLLA_RPC_HANDSHAKE_SEC` unvalidated** — `scylla-rpc-serve.rs:58-63`; `0` aborts every
  connection. Clamp to a `.max(1)` floor.
- **RPC-P3-9 · RPC transport limit (64 MiB default) < schema limit (512 MiB)** — a locally-loadable model
  can't be `export`ed/`diff`ed over RPC (ties to RPC-P2-1). Reconcile the limits.
- **RPC-P3-10 · `view` sends `size` the CLI never prints** — `scylla_rpc.capnp` / `lib.rs:301` vs
  `scylla-rpc-connect.rs:164-167`. Dead output field.
- **RPC-P3-11 · Implicit RefCell-no-borrow-across-await invariant** — all server methods; undocumented,
  and a future edit holding a borrow across `.await` panics under interleaving. Document/assert.
- **RPC-P3-12 · Non-UTF-8 token is a micro-oracle** — `lib.rs:91` fails faster than a valid-but-wrong
  token. Part of the constant-time hygiene story.
- **RPC-P3-13 · Needless clones + blanket lint allow** — `lib.rs:200-201` `.cloned().collect()` to count;
  `lib.rs:15` crate-wide `#![allow(clippy::needless_lifetimes)]` hides future hits.

### scylla-mcp / cli / serve / wasm
- **MCP-P3 · Errors bypass the untrusted envelope** — `lib.rs:220-222` returns `e` unwrapped; safe today
  (`PortError` Display has no artifact bytes) but a boundary gap. Wrap error text too. **[verified]**
- **MCP-P3 · `ping` returns `-32601`** — `lib.rs:225-227` has no `ping` arm; a client keepalive fails.
  **[verified]**
- **MCP-P3 · `initialize` ignores the client's `protocolVersion`** — `lib.rs:198-202` hardcodes
  `2024-11-05`. Echo/negotiate.
- **MCP-P3 · write/flush errors swallowed** — `main.rs:42-43`; on a closed client the server reads stdin
  forever. Shut down on write failure.
- **MCP/CLI-P3 · diff confidence keyed by name → collides on duplicate symbols + O(n²)** —
  `scylla-cli/src/main.rs:360-369,334-344` and `scylla-mcp/src/lib.rs:145-152`. Duplicate names
  (C `static`, C++ overloads) overwrite; per-line scans are quadratic. Key by `StableId`; precompute.
- **SERVE-P3 · No `nosniff`/CSP** — `scylla-serve/src/main.rs:105-109`. (Binding is `127.0.0.1` — correct.)
- **SERVE-P3 · Unbounded thread-per-connection** — `main.rs:77-81`. A localhost flood exhausts threads.
- **SERVE-P3 · Single 2048-byte read, no full-request read** — `main.rs:85-90`. A split/oversized request
  line mis-parses the path. Read until `\r\n\r\n`.
- **SERVE-P3 · No HTTP method check** — `main.rs:89`; `DELETE /x.scylla` returns the artifact. Reject
  non-GET/HEAD with 405.
- **SERVE-P3 · Out-of-range port silently falls back to 8000** — `main.rs:44-52`. Error on a bad port.
- **CLI-P3 · `--json` global strip is unescapable / silently ignored where unsupported** —
  `scylla-cli/src/main.rs:26-27`. Honor `--`; only strip for verbs that emit JSON.
- **CLI-P3 · Inconsistent "trouble" exit codes** — `materialize` uses `FAILURE`(1) for errors
  (`main.rs:441,451,457`) while read verbs reserve 1 for "diff differs" and use 2 for trouble. Use 2.
- **CLI-P3 · `.unwrap()` on infallible `serde_json`** — `main.rs:93,142,169,212,359,371`. Prefer
  `.expect("Value serialization is infallible")`.
- **MCP-P3 · Needless intermediate `Vec` in diff** — `lib.rs:156`. Fold the `filter` into the `map`.
- **WASM-P3 · `scylla_alloc` unbounded allocation** — `lib.rs:69-72`; a huge JS `len` traps the instance.
  Add a sanity cap.
- **WASM-P3 · Unchecked integer add in the sample generator** — `examples/gen_sample.rs:38-40`. Dev-only;
  `saturating_add`.

### scylla-model / schema / port / ingest
- **SCHEMA-P3 · Unknown `UserFact.kind` silently coerced to `Comment`, uncounted** — `lib.rs:25-31`
  (`model.capnp:63` even flags the TODO). Count/quarantine unknown kinds.
- **SCHEMA-P3 · `to_bytes` uses `.expect("write capnp message")`** — `lib.rs:109`. The only non-test panic
  surface in the loader crate (write path); return `Result` or document infallibility. **[verified]**
- **SCHEMA-P3 · Misleading reader-limit comment** — `lib.rs:226-233,240`. `MAX_NESTING=64` equals the
  capnp default and traversal was *loosened*, contradicting the "hardening" comment. Fix the comment or
  actually tighten nesting.
- **SCHEMA-P3 · Write path uses `len() as u32` / `i as u32`** — `lib.rs:41,50,56,60,64,68,72,78,85,94`.
  Silent truncation past 4.29 B elements; `.get(i as u32)` past a wrapped length can panic in `to_bytes`.
- **SCHEMA-P3 · `from_bytes` is `pub` and leaks `capnp::Error`** — `lib.rs:114`; bypasses the DD-036 total
  loader. Make `pub(crate)` or rename.
- **SCHEMA-P3 · Empty `producer`/`author` round-trips are lossy** — `lib.rs:101,198,203-210`;
  `Provenance{producer:"",confidence:50}` reloads as default (user/100), discarding confidence. Reject
  empty at construction or use a presence flag.
- **MODEL-P3 · `Provenance.confidence` never clamped to `0..=100`** — `lib.rs:182-195`, loader 208. An
  artifact can carry `confidence=200`, skewing merge trust math. Clamp on load.
- **MODEL-P3 · `Program::display_name` returns the first `Rename` fact** — `lib.rs:266-278`; facts aren't
  deduped on load, so two renames resolve arbitrarily (deterministic but unspecified). Dedup on load.
- **MODEL-P3 · `histogram_fingerprint` is a weak XOR fold with no field delimiter** — `lib.rs:146`.
  Harmless (a collision only flags "ambiguous"), but fold byte-by-byte for spread.
- **PORT-P3 · `functions()` uses `.unwrap()` on `view`** — `lib.rs:205`. Safe only by construction; use
  `filter_map`/`expect` with an invariant comment.
- **PORT-P3 · `diff_function_addrs` is "superseded" but public + untested** — `lib.rs:260-267`.
  `#[deprecated]` or remove.
- **INGEST-P3 · `id_of[&addr]` indexes a `HashMap`** — `lib.rs:77`; fragile invariant. `.expect(...)`
  (fixed by INGEST-P1-1 anyway).
- **INGEST-P3 · `parse_addr` quirks** — `lib.rs:50-52`. No uppercase `0X`; strips *all* leading `0x` runs;
  a bare decimal is parsed as hex. Tighten.
- **INGEST-P3 · `main.rs` indexes `args[0]`** — `main.rs:9` panics on an empty argv. Use `args.get(0)`.

### scylla-tui / lsp / engine / engine-service
- **ENGINE-P3 · `decompile` returns fake success, not `UNIMPLEMENTED`** — `EngineServer.java:510-514`
  returns a placeholder string; `scylla-engine/src/lib.rs:179-186` forwards it as real. Return
  `Status.UNIMPLEMENTED`.
- **ENGINE-P3 · `arch_hint` is dead** — always `String::new()` (`lib.rs:147`, `probe.rs:24`); the server
  never reads it. Wire it in or drop it.
- **ENGINE-P3 · `InfoReply.version` carries the mode, not a version** — `EngineServer.java:339-340`
  (`"0.1-warm"`/`"0.1-subprocess"`). Misleading; the real version is absent.
- **ENGINE-P3 · `Mutex::lock().unwrap()` can panic on poison** — `job.rs:67,82,93,105`. Low risk; handle
  `PoisonError` or document.
- **ENGINE-P3 · No client-side stream timeout/cancellation** — `lib.rs:155` awaits `stream.message()` with
  no deadline; a hung engine hangs the detached job forever. Add a client-side timeout.
- **ENGINE-P3 · New gRPC channel per call** — `connect_engine` re-dialed per `materialize`/`decompile`
  (`lib.rs:143,180`). Reuse a client.
- **LSP-P3 · `workspace_symbols` O(n²) and `ordered()` re-sorts every request** — `lib.rs:157,70-74`.
  Cache the ordering / build an id→line index.
- **LSP-P3 · `documentSymbol`/`workspace/symbol` names not untrusted-wrapped** — only `hover` wraps
  (`lib.rs:95-111,150-166`). An editor AI reading the outline sees raw attacker text.
- **ENGINE-P3 · `streamSnapshot` slurps the whole JSON into a Gson tree** — `EngineServer.java:441`.
  Self-produced (bounded in practice); consider streaming.
- **ENGINE-P3 · `getAsJsonArray("functions")` / field getters NPE on a missing key** —
  `EngineServer.java:454,457-460`. A producer bug surfaces as an opaque `INTERNAL: null`. Validate.
- **ENGINE-P3 · World-accessible control socket (0777)** — `EngineServer.java:596-599`; any local uid can
  drive the engine. Prefer a shared group + `rwxrwx---`. Also `sock.delete()` (587) unconditionally
  deletes whatever `SCYLLA_ENGINE_UDS` names — a misconfig footgun.
- **ENGINE-P3 · Untrusted `analyzeHeadless` log tail forwarded as the error description** —
  `EngineServer.java:417-421` echoes internal paths / hostile-binary output. Redact.
- **ENGINE-P3 · `tail()` can split a multibyte char** — `EngineServer.java:108-111` `substring` on char
  indices → cosmetic mojibake.
- **LSP-P3 · Non-UTF-8 header byte kills the server** — `main.rs:72` `read_line` errors → `break` → exit.
  `continue` past it.
- **TUI-P3 · `build_diff` keys provenance by display name → collides** — `app.rs:252,259`; `FUN_*`
  duplicates / blank names collide and show the wrong recovery rung. Key by `StableId`.
- **ENGINE-P3 · `Integer.parseInt(args[0])` (port) unvalidated** — `EngineServer.java:518` throws on a
  non-numeric arg and doesn't range-check 0–65535.
- **LSP-P3 · `Content-Length` header match is case-sensitive** — `main.rs:79`
  (`strip_prefix("Content-Length:")`); HTTP header names are case-insensitive.

### scylla-merge (docs / dead code)
- **MERGE-P3 · Stale pass counts in docs** — header line 12 says "Three passes", line 350 says "four
  passes", but the code runs **five** (exact/anchor/fuzzy/propagation/bsim); "strictly increasing in
  permissiveness" is loose.
- **MERGE-P3 · Header implies propagation is diff-only** — lines 22-25; `propagate_match` also runs in the
  merge path. Misleading.
- **MERGE-P3 · `best_old_match` doc is factually wrong** — lines 99-100 (see MERGE-P1-1).
- **MERGE-P3 · Dead branch in `jaccard`** — line 142 `if union == 0` is unreachable.
- **MERGE-P3 · `signature` uses `usize` → platform-width-dependent tuple** — line 44, hand-written in five
  places. Add a `type Signature` alias; pin to `u32`/`u64` if ever persisted/compared cross-host.
- **MERGE-P3 · Duplicate `StableId`s silently collapse in id→function maps** — lines 341-344, 845-846.
- **MERGE-P3 · `propagate_match` iterates a `HashSet`** — line 229; order-independent only because a
  top-tie collapses `second_s` to `best_s`. Iterate a `BTreeSet` to remove the footgun.
- **MERGE-P3 · Index-panic surfaces on malformed input** — `record_pair`/`key_a`/`key_b`
  (`a_fn[&aid]` etc., lines 652,713,718,786) and `group_unique` (`counts[k]`, 636) panic rather than
  fail-closed on an absent id.
- **MERGE-P3 · Merge path runs propagation-to-fixpoint then BSIM once** — lines 462-527 vs the diff path's
  per-rung fixpoint (847-894); a BSIM match can't feed back into propagation. Recall-only inconsistency.
- **MERGE-P3 · Prose drift** — BSIM comment says "~0.71" (line 489) vs "0.75" elsewhere (1317,1346);
  `#[allow(clippy::too_many_arguments)]` on `propagate_match`(192)/`feature_round`(752) hides a real 7–10
  arg smell; `merge_into` (542-547) appends carried facts without deduping against `new.facts` (re-running
  a merge duplicates facts).

### Workspace / CI / release / docs
- **WS-P3 · CI has no `--locked`** — `ci.yml` `cargo test`; the lockfile can drift silently. Add
  `--locked`.
- **WS-P3 · Stale CHANGELOG `[Unreleased]` link** — `CHANGELOG.md:194` compares `v0.5.0...HEAD` but 0.6.0
  is released; should be `v0.6.0...HEAD`.
- **WS-P3 · CI doesn't build/test the Java engine-service** except in `release.yml`. Add a build/test job.
- **WS-P3 · `release.yml` builds only `scylla-linux-x86_64`** — no other heads/platforms; no SLSA
  provenance attestation beyond the cosign blob signature. Scope choice; note it.

---

## What's already done right (don't "fix" these away)

- **engine-service has no path traversal / shell injection** — the client sends *bytes*, written to a
  server-controlled `Files.createTempFile` and passed to `analyzeHeadless` via a `ProcessBuilder`
  arg-list (no shell). Correct design.
- **The TUI `App` is genuinely pure/headless** — no I/O, time, or RNG; navigation is bounds-safe
  (`saturating_sub`, `.get()`, `recompute` clamps post-filter selection). The purity claim holds.
- **The total loader never *panics*** — every capnp read in `load`/`from_bytes` is `?`-propagated, no
  untrusted length drives a `with_capacity`, no recursion. The "never panics" half of the contract holds
  (the OOM/truncation *guarantees* are the gaps above).
- **`scylla-rpc` capability model is sound in shape** — no `Session` leaks before `login`; every verb is
  gated behind possession of the `Session` cap; no `unwrap()` in the server request paths.
- **The diff path (`diff_programs`) is the correctness reference** — it already enforces both-sided
  uniqueness + margin-gated reciprocity. The merge/collab fixes are "make the other paths match this one."
- **`materialize` fails closed** on caps before retaining chunks (the caps are just incomplete — ENGINE-P2-2).
- **Repo hygiene is clean** — `target/`, `fuzz/artifacts/`, `fuzz/corpus/` untracked; version consistent
  at 0.6.0 between `Cargo.toml` and `CHANGELOG.md`; exactly one `TODO` in the tree.

---

*Generated by a six-reviewer parallel pass with direct source verification of all P0 items and the
sharpest P1s. Line numbers are against the reviewed commit; re-check after any edit.*
