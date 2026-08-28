# Scylla — Architecture Review

- **Date:** 2026-07-11
- **Commit reviewed:** `main` @ `6fb100f` (clean tree, up to date with `origin/main`), version `0.7.0`.
- **Scope:** the 15-crate Rust workspace (`crates/*`, ~13.7 KLOC), the Java `engine-service`
  (`EngineServer.java`, ~613 LOC), the `fuzz/` lane, and the workspace/CI/build/dependency posture.
- **Method:** four parallel read-only reviewers — one per dimension (**Performance, Security, Usability,
  Scalability**) — swept the whole workspace, every finding anchored to `file:line`. Every P0/P1-class
  claim was **personally re-read against the source** before it entered this document; items that did not
  survive that pass were dropped or downgraded. Ground truth was established by building and testing on a
  clean toolchain: `cargo clippy --workspace --all-targets -- -D warnings` **passes**, `cargo test
  --workspace --locked` **passes (0 failures)**, and `cargo audit` was run against the committed
  `Cargo.lock`.
- **Relationship to [`RECOMMENDATIONS.md`](RECOMMENDATIONS.md):** that document was a *bug-level* review
  (2026-07-01, 93 findings) whose fixes shipped in v0.7.0. This is its **architecture-level successor.**
  It does **not** rehash fixed bugs — it spot-verifies that the eight highest-severity fixes still hold
  (they do; see §2), then raises the structural issues a line-by-line bug pass does not: algorithmic
  ceilings, the single-threaded serving model, the trust semantics of `collaborate`, the dependency
  supply chain, and the gap between what the docs promise and what the heads deliver.

This review is written in the Scylla register: exacting, opinionated, and unsentimental about the code.
That standard is a compliment to the platform, not an insult to it — a codebase that already enforces
`WRONG=0` and a total loader has earned a review that holds it to the next tier.

## Priority legend

| Pri | Meaning |
|-----|---------|
| **P0** | Critical — a correctness contract (`WRONG=0`) or a security boundary is actually breached at HEAD. |
| **P1** | High — a real bug, DoS, auth/trust weakness, or hard scaling wall reachable from a realistic input or a realistic target. |
| **P2** | Medium — robustness, an architectural ceiling that bites at plausible growth, a real inconsistency, a hardening gap. |
| **P3** | Low — polish, hygiene, doc drift, latent footguns. |

**Deployment caveat:** severities assume the posture the code *advertises* — a network-exposed head
(`0.0.0.0`, token possibly unset) fed a *hostile* artifact, and a *large* legitimate target (a
100k+-function firmware/browser-class binary). On a pure-loopback, single-analyst, small-binary dev
setup several P1s are materially lower risk. They are listed at their advertised-posture severity because
the heads ship `SCYLLA_*_TOKEN` + TLS and the platform's stated targets are firmware-scale — i.e. the code
is *designed* to be exposed and to be large.

## Summary counts

| Dimension | P0 | P1 | P2 | P3 |
|-----------|---:|---:|---:|---:|
| Performance | 0 | 1 | 5 | 3 |
| Security | 0 | 2 | 5 | 5 |
| Usability | 0 | 3 | 9 | 3 |
| Scalability | 0 | 3 | 4 | 3 |

No P0. The v0.7.0 hardening pass closed every breach the prior review found, and this pass found no new
one. The P1s are architectural, not "the loader panics" — which is exactly where a platform at this
maturity should be spending its worry.

## Remediation status — 2026-07-24

The findings below remain a point-in-time review of `main` at `6fb100f`; their evidence and line numbers
have not been rewritten to pretend they were discovered later. This table records the current disposition
after `1012dcd` on `fix/review-backlog-3-9`. **Resolved on branch** and **Partial on branch** remain open
in the trackers until the branch is merged.

| Finding | Current status | Trackers |
|---|---|---|
| PERF-P1-1 | **OPEN** | [Codeberg #119](https://codeberg.org/CryptoJones/Scylla/issues/119) · [GitHub #10](https://github.com/CryptoJones/Scylla/issues/10) |
| PERF-P2-1 | **OPEN** | [Codeberg #120](https://codeberg.org/CryptoJones/Scylla/issues/120) · [GitHub #11](https://github.com/CryptoJones/Scylla/issues/11) |
| PERF-P2-2 | **OPEN** | [Codeberg #121](https://codeberg.org/CryptoJones/Scylla/issues/121) · [GitHub #12](https://github.com/CryptoJones/Scylla/issues/12) |
| PERF-P2-3 | **OPEN** | [Codeberg #122](https://codeberg.org/CryptoJones/Scylla/issues/122) · [GitHub #13](https://github.com/CryptoJones/Scylla/issues/13) |
| PERF-P2-4 | **OPEN** | [Codeberg #123](https://codeberg.org/CryptoJones/Scylla/issues/123) · [GitHub #14](https://github.com/CryptoJones/Scylla/issues/14) |
| PERF-P2-5 | **OPEN** | [Codeberg #124](https://codeberg.org/CryptoJones/Scylla/issues/124) · [GitHub #15](https://github.com/CryptoJones/Scylla/issues/15) |
| PERF-P3-1 | **OPEN** | [Codeberg #125](https://codeberg.org/CryptoJones/Scylla/issues/125) · [GitHub #16](https://github.com/CryptoJones/Scylla/issues/16) |
| PERF-P3-2 | **OPEN** | [Codeberg #126](https://codeberg.org/CryptoJones/Scylla/issues/126) · [GitHub #17](https://github.com/CryptoJones/Scylla/issues/17) |
| PERF-P3-3 | **OPEN** | [Codeberg #127](https://codeberg.org/CryptoJones/Scylla/issues/127) · [GitHub #18](https://github.com/CryptoJones/Scylla/issues/18) |
| SEC-P1-1 | **OPEN** | [Codeberg #128](https://codeberg.org/CryptoJones/Scylla/issues/128) · [GitHub #19](https://github.com/CryptoJones/Scylla/issues/19) |
| SEC-P1-2 | **OPEN** | [Codeberg #129](https://codeberg.org/CryptoJones/Scylla/issues/129) · [GitHub #20](https://github.com/CryptoJones/Scylla/issues/20) |
| SEC-P2-1 | **OPEN** | [Codeberg #130](https://codeberg.org/CryptoJones/Scylla/issues/130) · [GitHub #21](https://github.com/CryptoJones/Scylla/issues/21) |
| SEC-P2-2 | **OPEN** | [Codeberg #131](https://codeberg.org/CryptoJones/Scylla/issues/131) · [GitHub #22](https://github.com/CryptoJones/Scylla/issues/22) |
| SEC-P2-3 | **OPEN** | [Codeberg #132](https://codeberg.org/CryptoJones/Scylla/issues/132) · [GitHub #23](https://github.com/CryptoJones/Scylla/issues/23) |
| SEC-P2-4 | **OPEN** | [Codeberg #133](https://codeberg.org/CryptoJones/Scylla/issues/133) · [GitHub #24](https://github.com/CryptoJones/Scylla/issues/24) |
| SEC-P2-5 | **PARTIAL ON BRANCH** — vulnerable web TLS chain removed and `cargo audit` added; `cargo-deny` and action SHA pinning remain open | [Codeberg #134](https://codeberg.org/CryptoJones/Scylla/issues/134) · [GitHub #4](https://github.com/CryptoJones/Scylla/issues/4) |
| SEC-P3-1 | **OPEN** | [Codeberg #135](https://codeberg.org/CryptoJones/Scylla/issues/135) · [GitHub #25](https://github.com/CryptoJones/Scylla/issues/25) |
| SEC-P3-2 | **OPEN** | [Codeberg #136](https://codeberg.org/CryptoJones/Scylla/issues/136) · [GitHub #26](https://github.com/CryptoJones/Scylla/issues/26) |
| SEC-P3-3 | **OPEN** | [Codeberg #137](https://codeberg.org/CryptoJones/Scylla/issues/137) · [GitHub #27](https://github.com/CryptoJones/Scylla/issues/27) |
| SEC-P3-4 | **OPEN** | [Codeberg #138](https://codeberg.org/CryptoJones/Scylla/issues/138) · [GitHub #28](https://github.com/CryptoJones/Scylla/issues/28) |
| SEC-P3-5 | **PARTIAL ON BRANCH** — threat model corrected; fail-open network defaults remain open | [Codeberg #139](https://codeberg.org/CryptoJones/Scylla/issues/139) · [GitHub #6](https://github.com/CryptoJones/Scylla/issues/6) |
| USE-P1-1 | **OPEN** | [Codeberg #140](https://codeberg.org/CryptoJones/Scylla/issues/140) · [GitHub #29](https://github.com/CryptoJones/Scylla/issues/29) |
| USE-P1-2 | **RESOLVED ON BRANCH** — setup guide added and personal path removed | [Codeberg #141](https://codeberg.org/CryptoJones/Scylla/issues/141) · [GitHub #9](https://github.com/CryptoJones/Scylla/issues/9) |
| USE-P1-3 | **OPEN** | [Codeberg #142](https://codeberg.org/CryptoJones/Scylla/issues/142) · [GitHub #30](https://github.com/CryptoJones/Scylla/issues/30) |
| USE-P2-1 | **PARTIAL ON BRANCH** — parity overclaim removed; CLI mutation verbs remain absent | [Codeberg #143](https://codeberg.org/CryptoJones/Scylla/issues/143) · [GitHub #7](https://github.com/CryptoJones/Scylla/issues/7) |
| USE-P2-2 | **OPEN** — docs no longer claim parity, but `merge` remains absent from seven heads | [Codeberg #144](https://codeberg.org/CryptoJones/Scylla/issues/144) · [GitHub #7](https://github.com/CryptoJones/Scylla/issues/7) |
| USE-P2-3 | **OPEN** | [Codeberg #145](https://codeberg.org/CryptoJones/Scylla/issues/145) · [GitHub #31](https://github.com/CryptoJones/Scylla/issues/31) |
| USE-P2-4 | **OPEN** | [Codeberg #146](https://codeberg.org/CryptoJones/Scylla/issues/146) · [GitHub #32](https://github.com/CryptoJones/Scylla/issues/32) |
| USE-P2-5 | **OPEN** — parity overclaim removed, but cross-head naming drift remains | [Codeberg #147](https://codeberg.org/CryptoJones/Scylla/issues/147) · [GitHub #7](https://github.com/CryptoJones/Scylla/issues/7) |
| USE-P2-6 | **OPEN** | [Codeberg #148](https://codeberg.org/CryptoJones/Scylla/issues/148) · [GitHub #33](https://github.com/CryptoJones/Scylla/issues/33) |
| USE-P2-7 | **OPEN** | [Codeberg #149](https://codeberg.org/CryptoJones/Scylla/issues/149) · [GitHub #34](https://github.com/CryptoJones/Scylla/issues/34) |
| USE-P2-8 | **OPEN** | [Codeberg #150](https://codeberg.org/CryptoJones/Scylla/issues/150) · [GitHub #35](https://github.com/CryptoJones/Scylla/issues/35) |
| USE-P2-9 | **OPEN** | [Codeberg #151](https://codeberg.org/CryptoJones/Scylla/issues/151) · [GitHub #36](https://github.com/CryptoJones/Scylla/issues/36) |
| USE-P3-1 | **OPEN** | [Codeberg #152](https://codeberg.org/CryptoJones/Scylla/issues/152) · [GitHub #37](https://github.com/CryptoJones/Scylla/issues/37) |
| USE-P3-2 | **OPEN** | [Codeberg #153](https://codeberg.org/CryptoJones/Scylla/issues/153) · [GitHub #38](https://github.com/CryptoJones/Scylla/issues/38) |
| USE-P3-3 | **OPEN** | [Codeberg #154](https://codeberg.org/CryptoJones/Scylla/issues/154) · [GitHub #39](https://github.com/CryptoJones/Scylla/issues/39) |
| SCALE-P1-1 | **OPEN** | [Codeberg #155](https://codeberg.org/CryptoJones/Scylla/issues/155) · [GitHub #40](https://github.com/CryptoJones/Scylla/issues/40) |
| SCALE-P1-2 | **OPEN** | [Codeberg #156](https://codeberg.org/CryptoJones/Scylla/issues/156) · [GitHub #41](https://github.com/CryptoJones/Scylla/issues/41) |
| SCALE-P1-3 | **OPEN** | [Codeberg #157](https://codeberg.org/CryptoJones/Scylla/issues/157) · [GitHub #42](https://github.com/CryptoJones/Scylla/issues/42) |
| SCALE-P2-1 | **OPEN** | [Codeberg #158](https://codeberg.org/CryptoJones/Scylla/issues/158) · [GitHub #43](https://github.com/CryptoJones/Scylla/issues/43) |
| SCALE-P2-2 | **OPEN** | [Codeberg #159](https://codeberg.org/CryptoJones/Scylla/issues/159) · [GitHub #44](https://github.com/CryptoJones/Scylla/issues/44) |
| SCALE-P2-3 | **OPEN** | [Codeberg #160](https://codeberg.org/CryptoJones/Scylla/issues/160) · [GitHub #45](https://github.com/CryptoJones/Scylla/issues/45) |
| SCALE-P2-4 | **OPEN** | [Codeberg #161](https://codeberg.org/CryptoJones/Scylla/issues/161) · [GitHub #46](https://github.com/CryptoJones/Scylla/issues/46) |
| SCALE-P3-1 | **OPEN** | [Codeberg #162](https://codeberg.org/CryptoJones/Scylla/issues/162) · [GitHub #47](https://github.com/CryptoJones/Scylla/issues/47) |
| SCALE-P3-2 | **OPEN** | [Codeberg #163](https://codeberg.org/CryptoJones/Scylla/issues/163) · [GitHub #48](https://github.com/CryptoJones/Scylla/issues/48) |
| SCALE-P3-3 | **OPEN** | [Codeberg #164](https://codeberg.org/CryptoJones/Scylla/issues/164) · [GitHub #49](https://github.com/CryptoJones/Scylla/issues/49) |

---

## 1. Executive summary & verdict

Scylla at v0.7.0 is a genuinely well-structured hexagonal codebase whose *correctness* and *panic-safety*
contracts hold under adversarial re-reading. The v0.7.0 remediation is real: the merge WRONG=0 holes, the
prompt-injection envelope, the constant-time auth, the total-loader caps, and the id-minting collisions
are all fixed at HEAD (§2). Clippy is clean under `-D warnings` and the full test suite is green.

The problems are now **architectural**, and they cluster into four roots:

1. **The serving model is single-threaded per head and the matcher is O(N²).** Every network head resolves
   exactly one request at a time on one thread, and the diff/merge core recomputes O(N²) feature
   comparisons — each allocating a fresh map/set — inside a fixpoint loop. Neither is a bug at
   demo scale; both are a wall at the firmware scale the platform advertises. This is the single biggest
   gap between what Scylla claims to be (a firmware-differ, a multi-analyst service) and what it can do
   today.
2. **`collaborate` derives trust from an untrusted artifact's own self-asserted `confidence`.** A hostile
   `.scylla` can stamp a contradicting fact at confidence 100 and *silently* overwrite any local fact
   below the max tier — machine-derived facts, or facts carried in from a prior merge. This contradicts
   the platform's own "foreign facts are surfaced, never silent" contract.
3. **The dependency supply chain is unaudited and the docs lie about the deployment surface.** `cargo
   audit` flags a 7.5-HIGH `rustls` advisory reachable through both web heads; there is no `cargo-deny`
   gate; `THREAT-MODEL.md` still claims "no networked head yet" while four networked, *writable* heads
   ship.
4. **The docs promise "the same verbs on all nine heads" and the code does not deliver.** The CLI cannot
   annotate; `merge` exists on 2 of 9 heads; `collaborate` is reachable from none; the warm engine is
   documented as "not built yet" but is fully implemented. A new user's first `cargo build` fails on
   undocumented native prerequisites.

**Verdict:** ship-quality core, prototype-quality edges. The core model, loader, and matcher *logic* are
sound. The **serving concurrency, the collaboration trust model, the supply-chain gate, and the
documentation** are where the architecture has not yet caught up to the ambition. None of this is a
five-alarm fire; all of it is the difference between "impressive single-analyst tool" and "the
firmware-scale collaborative platform the README describes." Fix the four roots in §7 and the gap closes.

---

## 2. Baseline — status of the v0.7.0 remediation

Spot-verified at HEAD (`6fb100f`). **All eight highest-severity v0.7.0 fixes hold.**

| Fixed item | Location at HEAD | Result |
|---|---|---|
| Merge both-sided uniqueness + reciprocal-best | `crates/scylla-merge/src/lib.rs:471-480` (EXACT requires `old_unique && new_ids.len()==1`), `:895-901` (`feature_round` reciprocal-best), `:1073-1076` (collaborate both-sided) | **PASS** |
| MCP `<untrusted-data>` sentinel neutralization | `crates/scylla-mcp/src/lib.rs:42-45` | **PASS** (residual: SEC-P2-1) |
| LSP envelope sentinel neutralization | `crates/scylla-lsp/src/lib.rs:241-243` | **PASS** (residual: SEC-P2-1) |
| Constant-time bearer/token compare (http/graphql/rpc) | `scylla-http/src/main.rs:35-42`, `scylla-graphql/src/main.rs:33-40`, `scylla-rpc/src/lib.rs:408-414` | **PASS** |
| Total-loader string truncation + decode caps | `scylla-schema/src/lib.rs:56-75`, `:335-344`, `:40-52`, `:402-483` | **PASS** |
| IdMinter (ingest + engine) — distinct ids on dup/unparseable addr | `scylla-ingest/src/lib.rs:62-75`, `scylla-engine/src/lib.rs:60-66`, `scylla-model/src/lib.rs:34-42` | **PASS** |
| Engine process-tree kill | `EngineServer.java:451-452`, `:268-269` | **PASS** |
| TLS fail-closed on half-config | `scylla-http/src/main.rs:168-179`, `scylla-graphql/src/main.rs:101-112`, `scylla-rpc-serve.rs:98-109` | **PASS** |

Nothing carried forward. Two things the v0.7.0 notes claimed as future work but which are already **done**
at HEAD and should stop being described as pending: `Session::functions()` is O(N+E) (not the old O(N²)),
and the loader is zero-copy `read_message_from_flat_slice` (not the old copying `read_message`).

---

## 3. Performance

### PERF-P1-1 · `diff_programs` is O(rounds · N²) with a fresh allocation per comparison — the dominant cost at any realistic scale **[verified]**
`crates/scylla-merge/src/lib.rs:962-1009`. The fixpoint `loop` calls `feature_round` three times per
iteration (ANCHOR `:967`, BSIM `:981`, FUZZY `:994`). `feature_round` (`:868-907`) pairs `a_elig × b_elig`:
for each `aid` it runs `best_unique` over all of `b_elig` (`:889`) **and** a reciprocal `best_unique` over
all of `a_elig` (`:897`) — O(|a_elig|·|b_elig|) `score` calls per round. Worse, the score functions
allocate on every call: `anchor_set` (`:140-147`) builds a fresh `HashSet<&str>` per invocation, `cosine`
(`:59`) rebuilds two `HashMap`s, `bsim_similarity` (`:355`) rebuilds one. The whole ladder re-runs every
fixpoint iteration. **Scenario:** diff two 100k-function builds compiled with different flags (a recompile
or cross-arch pair — the *stated* use case) so the EXACT pass misses most functions and
`|a_elig|≈|b_elig|≈90k`. One anchor round is ~90k·180k ≈ 1.6×10¹⁰ Jaccards, each allocating a set;
×3 rounds ×several iterations. This is the function behind `POST /api/diff`, `Session::diff`, the CLI
`diff`, and the wasm differ — hours-to-days of CPU and enormous allocation churn, and on the RPC head it
blocks the single thread for every other peer. **Advised:** hoist per-function feature caches out of the
`loop` — build `anchor_set` (as a sorted `&[&str]` for linear-merge Jaccard), the mnemonic/trigram maps
**and their L2 norms**, and the bsim map+norm **once** per function, then make `score` do allocation-free
lookups; additionally bucket candidates via LSH/MinHash (Ghidra's BSim already uses LSH — reuse the
vector) so each function compares against its band, turning O(N²) into O(N·b). Add a function-count guard
that falls back to signature-bucket-only diff above ~20k leftovers with an `--exhaustive` opt-in. This is
the same class the prior review flagged as MERGE-P2 and it is **not** applied at HEAD.

### PERF-P2-1 · `reanchor_facts`/merge recompute features per pair and rebuild `rev_matched` per call
`crates/scylla-merge/src/lib.rs:504-568` (ANCHOR/FUZZY passes recompute `anchor_set`/`similarity` per
candidate), `:331-332` (`propagate_match` allocates `rev_matched: HashMap` fresh on every call inside the
fixpoint `:577-594`). O(F·N·set) where F = fact-carrying functions. **Scenario:** re-anchoring a
heavily-annotated program (thousands of facts) onto a fresh 50k-function rebuild. **Advised:** reuse the
same per-function caches as PERF-P1-1; build `rev_matched` once per iteration (or maintain it
incrementally) instead of per `propagate_match`.

### PERF-P2-2 · Port query paths do full-artifact scans per call with no cached index
`crates/scylla-port/src/lib.rs`: `view` (`:242-246`) → `func` linear `find` (`:165-171`) + `callers`
scan (`:178-185`) + a `name_of` closure calling `display_name`, and `display_name`
(`scylla-model/src/lib.rs:274-285`) scans **all facts** per call → one `view` is O(N + E + callees·facts).
`Session` (`:109-115`) caches nothing, so every network head re-pays these scans on every request.
**Scenario:** an editor or dashboard walking a 100k-function call graph fires one such request per
navigation. **Advised:** build `id → &Function`, a caller-adjacency map, and a `display_name` index once,
store them on `Session`, invalidate on annotation; `view`/`callers`/`name_of` become O(callees).

### PERF-P2-3 · `Session::search` materializes every function's full view before filtering
`crates/scylla-port/src/lib.rs:273-282`. `search` calls `self.functions(zoom)` — building N heavyweight
`FunctionView`s, each allocating `callees`/`callers` `Vec<String>` — then filters by substring. A query
matching a handful of functions in a 100k-function program builds and discards ~100k views; the RPC
`search` (`scylla-rpc/src/lib.rs:175-180`) throws away everything but `v.id`. **Advised:** filter by
display name first (via the PERF-P2-2 index), build views only for matches, and give id-only callers a
lightweight path.

### PERF-P2-4 · Java cold `materialize` is the default and pays full JVM+Ghidra init per request
`engine-service/.../EngineServer.java:613` (warm is opt-in via `SCYLLA_ENGINE_WARM`), so out of the box
every `Materialize` forks a fresh `analyzeHeadless` JVM (`:421-429`, ~6s host init per the class doc) and
creates+deletes a fresh temp project (`:418`, `:481-483`). Separately, `streamSnapshot` (`:493-494`) does
`JsonParser.parseString(Files.readString(out))` — the entire snapshot into one `String` then a full Gson
tree, doubling peak heap, before it "streams." For the advertised 200 MB-firmware target that is a
multi-hundred-MB spike. **Advised:** default the warm pool on (or document the cold cost prominently) so
the init amortizes; replace `readString`+tree with a streaming `Gson JsonReader` emitting `FunctionChunk`s
so snapshot memory is O(one function).

### PERF-P2-5 · No pagination on any list verb — full-model responses everywhere
RPC `functions` builds one capnp capability per function (`scylla-rpc/src/lib.rs:145-148`); HTTP
(`scylla-http/src/main.rs:360-368`), GraphQL (`scylla-graphql/src/schema.rs:209-214`), and wasm
(`scylla-wasm/src/lib.rs:126-132`) each serialize the entire model to one JSON blob. A single
`/api/functions` against a 100k-function artifact returns a 100k-element response. **Advised:** add a
server-capped `limit`/`offset` (or cursor) to every list verb, consistently across heads. (This is also
USE-P2-9 — the same gap seen from the usability lens.)

### PERF-P3-1 · Loader allocates a per-function `HashSet` even when `edge_provenance` is empty
`crates/scylla-schema/src/lib.rs:442-445` builds `callee_set` unconditionally though it is used only to
`retain` the (documented-as-sparse) `edge_provenance`. 100k functions → 100k throwaway sets. **Advised:**
`if !func.edge_provenance.is_empty() { … }`.

### PERF-P3-2 · The "zero-copy" load claim is segment-level only
`crates/scylla-schema/src/lib.rs:179` correctly avoids the copying read, but `decode_bytes` (`:190-323`)
then `.to_owned()`s every string and `Vec`-copies every list into a fully-owned `Program`, and `load`
walks it all again to truncate. There is no borrowed/lazy read path, so read-only heads (http/graphql/rpc/
wasm never mutate bodies, only append facts) deep-copy the whole artifact to answer one query. Defensible
under DD-002, but the "zero-copy" wording oversells it. **Advised:** either soften the claim or add a
borrowed `Session` over the capnp reader for the read-only heads (see SCALE-P2-3).

### PERF-P3-3 · wasm links the full merge engine + `serde_json` for flat output; `connect_engine` re-dials per call
`crates/scylla-wasm/src/lib.rs` pulls the entire `scylla-merge` engine + `serde_json` into the `.wasm`
though it emits only flat JSON. `crates/scylla-engine/src/lib.rs:180,219` rebuild a tonic channel per
`materialize`/`decompile`. **Advised:** hand-roll the wasm JSON writer to drop `serde_json`; hold one
cloneable `EngineClient<Channel>` on the engine head.

---

## 4. Security

### SEC-P1-1 · `collaborate` derives trust from an untrusted artifact's self-asserted `confidence` — silent overwrite of local facts **[verified]**
`crates/scylla-merge/src/lib.rs:1093-1097`. On a fact disagreement, `collaborate` auto-resolves in favour
of whichever side carries the higher `Provenance::confidence` (`CONFIDENCE_MARGIN = 5`, `:1042`), counting
it as `resolved_by_confidence` and **never surfacing a `Conflict`**:
```rust
if incoming_conf > base_conf && incoming_conf - base_conf > CONFIDENCE_MARGIN {
    to_replace.push(fact.retarget(tid));      // higher-confidence incoming SILENTLY wins
    report.resolved_by_confidence += 1;
}
```
`confidence` is attacker-controlled data read straight out of the `.scylla` (the loader only clamps it to
≤100, `scylla-schema/src/lib.rs:451,477`). A fresh analyst rename defaults to confidence 100
(`scylla-model/src/lib.rs:200`), so the *max* tier is tie-protected — **but any base fact legitimately
below 95** (engine-derived facts at confidence 45/40, or facts carried from a prior merge — the crate's
own tests use 85/90) **is silently replaced** by a hostile artifact that stamps its contradicting fact at
confidence 100, `producer:"user"`. **Attack:** a shared/foreign `.scylla` (untrusted per THREAT-MODEL) fed
to `merge_from`/`collaborate` — reachable from `scylla-mcp/src/lib.rs:197`, `scylla-wasm/src/lib.rs:257`,
`scylla-cli/src/main.rs:285` — silently rewrites the analyst's sub-max durable facts (asset zero,
DD-004/005) with no prompt, directly contradicting the "foreign facts are surfaced, never silent"
contract. **Advised:** do not derive trust from an untrusted artifact's own `confidence`. Treat
cross-provenance disagreements as conflicts unconditionally, or scope confidence-resolution to
same-`producer`/locally-originated facts; never auto-`to_replace` a base fact from an untrusted
`incoming`. This is the single most important finding in the review — it is a `WRONG=0`-adjacent breach
that only isn't a P0 because it requires the analyst to import a hostile artifact.

### SEC-P1-2 · GraphQL has no depth/complexity/alias limit — the expensive `diff` resolver is alias-amplifiable **[verified]**
`crates/scylla-graphql/src/main.rs:209` runs `gql.execute_sync(root, context)` with juniper's default
(unbounded) validation, and the `diff` resolver (`schema.rs:270`) base64-decodes and runs a full
`Session::from_artifact` — the entire loader, up to the 512 MiB traversal ceiling — **per invocation.**
**Attack:** one POST within the 64 MiB body cap carries hundreds of aliased `diff` fields
(`{a:diff(...){…} b:diff(...){…} …}`), each triggering a full artifact decode+load → CPU/allocation
amplification and head DoS. (This is GQL-P1-3 from the prior review — flagged, never fixed.) **Advised:**
set a juniper depth + complexity limit, reject `diff` beyond a small per-request count, and cap the
resolver's decoded-artifact size well below the loader ceiling.

### SEC-P2-1 · `neutralize_fence` is exact-match/case-sensitive — the envelope re-opens with a case or whitespace variant
`crates/scylla-mcp/src/lib.rs:42-45`, `crates/scylla-lsp/src/lib.rs:241-243`. Only the exact lowercase,
no-whitespace `</untrusted-data>` is defused. A hostile name/comment containing `</UNTRUSTED-DATA>`,
`</untrusted-data >`, or `< /untrusted-data>` survives verbatim; a lenient LLM parser — the exact failure
mode DD-035 defends — may treat it as the close tag. Same class as the *fixed* MCP-P0-1/LSP-P0-1, re-opened
by a variant. **Advised:** neutralize case-insensitively tolerating intra-tag whitespace
(`(?i)<\s*/?\s*untrusted-data\s*>`), or switch to a random per-response nonce boundary the content cannot
predict.

### SEC-P2-2 · Engine TCP mode is unauthenticated, plaintext, binds all interfaces, and is the Docker default
`engine-service/.../EngineServer.java:669-671` — `ServerBuilder.forPort(port)` binds `0.0.0.0`, no TLS, no
token; the safe path (UDS + `--network none`) is opt-in via `SCYLLA_ENGINE_UDS` (`:643`) and the Dockerfile
`ENTRYPOINT` defaults to TCP `50051`. Run without UDS and anyone routable can submit arbitrary binaries
into the Ghidra parser — the primary RCE surface (DD-034) — with no containment. **Advised:** refuse to
start the TCP listener unless an explicit `SCYLLA_ENGINE_ALLOW_TCP=1` is set, bind loopback by default,
document UDS as the only supported production transport.

### SEC-P2-3 · Engine gRPC socket is world-accessible (`chmod 777`) with no channel auth
`EngineServer.java:662-666` chmods the UDS to `rwxrwxrwx`; `run-sandboxed.sh:10-11` `chmod 777`s the socket
dir; there is no token on the gRPC surface. Any local user can drive the sandboxed engine — submit
binaries, consume the 4 GiB/2-CPU budget, receive decompilation. **Advised:** restrict the socket dir to
the client uid/gid (0770) and run the container with a matching supplementary group; the "different uid"
convenience should be a group, not world.

### SEC-P2-4 · DD-034 containment is advisory, not code-enforced
`crates/scylla-engine/src/lib.rs:174` — `materialize` connects to whatever `endpoint` string it is handed
(plaintext, `:166`) with nothing verifying it is the locked-down UDS instance. A typo'd endpoint pointed
at a bare `EngineServer` silently bypasses the entire sandbox. **Advised:** default the endpoint to the UDS
path, warn loudly on any non-UDS endpoint, and treat DD-034 as a code-enforced default rather than an ops
convention.

### SEC-P2-5 · No `cargo-deny`/advisory gate, and the OIDC-privileged release lane consumes unpinned actions
`cargo audit` at HEAD reports **2 vulnerabilities**: `rustls 0.20.9` (RUSTSEC-2024-0336, **7.5 HIGH**,
`complete_io` infinite-loop on hostile network input) and `ring 0.16.20` (RUSTSEC-2025-0009 AES panic),
**both reachable through `tiny_http` behind `scylla-http` and `scylla-graphql`** (`cargo tree -i` confirms
the path), plus unmaintained `rustls-pemfile 0.2.1`/`paste` and unsound-flagged `anyhow 1.0.102`/`lru
0.12.5`. CI runs clippy+tests but **no** RUSTSEC/yanked/license scan (there is no `deny.toml`), and
`.github/workflows/release.yml` holds `contents:write`+`id-token:write`+`packages:write` while consuming
`sigstore/cosign-installer@v3`, `softprops/action-gh-release@v2`, `docker/login-action@v3`,
`dtolnay/rust-toolchain@stable` by floating tag. A mutated tag on any of those runs inside the
keyless-signing job and undercuts the signature it publishes. **Advised:** upgrade the web heads off
`tiny_http`'s vulnerable `rustls`/`ring` (or off `tiny_http`); add a `deny.toml` + `cargo deny check` CI
gate; pin every third-party action to a full commit SHA, especially in `release.yml`.

### SEC-P3-1 · LSP `documentSymbol` surfaces binary-derived names unwrapped
`crates/scylla-lsp/src/lib.rs:50`. Only `hover` is enveloped (`:116-126`); the symbol tree returns raw
function names from the hostile binary with no `<untrusted-data>` delimiting — an editor-side AI outline
reads attacker text undelimited. **Advised:** document the residual; where an AI consumer is possible,
strip instruction-like control sequences from symbol labels (they can't be enveloped without breaking the
outline).

### SEC-P3-2 · GraphQL session `Mutex` poisoning is a latent permanent DoS
`crates/scylla-graphql/src/schema.rs:27,275` — `.lock().expect("session lock")`. The per-request
`catch_unwind` (`main.rs:159`) survives a resolver panic, but a panic while the lock is held poisons the
`Mutex`, so every subsequent `.lock().expect(...)` panics → all future requests permanently 500.
**Advised:** `.lock().unwrap_or_else(|e| e.into_inner())`.

### SEC-P3-3 · Token env handling inconsistent — a whitespace token is "set" on RPC, "unset" on http/graphql
`scylla-rpc-serve.rs:56-58` filters `!t.is_empty()`; http/graphql filter `!t.trim().is_empty()`
(`http/main.rs:144`, `graphql/main.rs:80`). A `SCYLLA_RPC_TOKEN=" "` is accepted as a real (trivially
guessable) token on RPC but treated as unset elsewhere. **Advised:** trim consistently and reject blank
tokens uniformly.

### SEC-P3-4 · `producer` provenance is unauthenticated free text
`crates/scylla-model/src/lib.rs:184-192` — a hostile artifact can stamp `producer:"user"` on
machine-forged facts so they render as analyst-authored (DD-007). Not used for authz (only `confidence`
is, SEC-P1-1), so impact is attribution spoofing — but provenance shown to the analyst is unauthenticated.
**Advised:** distinguish locally-originated from imported `producer` values in the UI, or sign/scope
provenance on ingest.

### SEC-P3-5 · Fail-open is the default posture and the threat model is stale
Unset `SCYLLA_*_TOKEN` = fully open, any-token = full read+write+export with no authz granularity
(`scylla-http/main.rs:136-144,200-204`; graphql `:73-80`; rpc `:54-58`). By design and loudly announced,
loopback by default — but `THREAT-MODEL.md` still asserts "no networked head yet / auth deliberately
deferred" while four networked heads (`http/graphql/rpc/serve`) ship `POST rename/retype/comment`,
`/api/export`, and a `diff` that loads attacker bytes. **Advised:** update the threat model to cover the
shipped heads; consider defaulting to closed (require an explicit `--open`/`SCYLLA_*_OPEN=1`) so an
operator can't expose a writable, model-exfiltrating head by merely forgetting a token.

---

## 5. Usability

### USE-P1-1 · A fresh clone fails to build on undocumented native prerequisites
`crates/scylla-engine/build.rs:2` needs `protoc`; `crates/scylla-schema/build.rs` and
`crates/scylla-rpc/build.rs` need the `capnp` compiler — yet `README.md` has no getting-started/prereq
section and `CONTRIBUTING.md:24` only claims `cargo test --workspace` is green. A new user clones, runs
`cargo build`, and gets a cryptic `protoc`/`capnp not found` before anything runs. *(Confirmed
first-hand during this review: the workspace would not build until `protobuf` and `capnproto` were
installed.)* **Advised:** add a "Prerequisites" block (Rust stable + `wasm32-unknown-unknown`, `protoc`,
`capnp`, JDK 21 for the engine) and make each `build.rs` `panic!` with the missing tool + install command.

### USE-P1-2 · The engine-service — the *primary* materialize path — has no runnable setup docs and ships a hardcoded personal path
`engine-service/run-sandboxed.sh:7` defaults `GHIDRA_DIST` to
`/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0`, assumes a
`scylla-engine-service:dev` image no documented step builds, and nothing chains `gradle installDist` →
`docker build` → `run-sandboxed.sh`. README/CONTRIBUTING never mention Gradle, Docker, GayHydra, or 50051.
A user who wants the advertised `scylla materialize …` path cannot stand up an engine at all. **Advised:**
add `engine-service/README.md` with the full build-and-run recipe, replace the hardcoded `GHIDRA_DIST`
with an unset-and-error check, link it from README.

### USE-P1-3 · `LoadReport` quarantine warnings are silently dropped on every head — "never silently wrong" violated
`Session::load_report()` exists (`crates/scylla-port/src/lib.rs:133`) and the loader carefully counts
dropped/truncated data (`scylla-schema/src/lib.rs:349`), but a workspace-wide grep confirms **no head**
(cli/mcp/http/graphql/rpc/tui/lsp/serve/wasm) ever calls it. A user loads a partially-corrupt/truncated
artifact, gets a silently reduced model, and receives **zero** warning — a direct violation of the
platform's own ethos. **Advised:** after `Session::from_artifact`, if `!load_report().clean()`, emit a
stderr warning (CLI/servers) / MCP notice / TUI status line with the counts; add a `--strict` that exits
non-zero on a dirty load.

### USE-P2-1 · The CLI cannot annotate at all, despite the "same verbs" claim
`crates/scylla-cli/src/main.rs:29-42` dispatches only materialize/diff/info/functions/search/view/callers/
merge — **no** `rename`/`retype`/`comment`/`export`, all of which exist on MCP/HTTP/GraphQL/RPC/LSP. The
primary solo terminal analyst can browse but cannot rename a function and persist it from the CLI, while
`README.md:71-72` calls every head a projection of "the *same* verbs (navigate / annotate / diff /
merge / export)." **Advised:** add `scylla rename|retype|comment <artifact> <id> <value> [out]` and `scylla
export`, or scope the README claim.

### USE-P2-2 · `merge` is missing from 7 of 9 heads
`merge` exists only in CLI (`main.rs:42`) and MCP; a grep for merge/`collaborate` in http/graphql/rpc
returns nothing, though README/ARCHITECTURE claim all nine heads project it. **Advised:** add a merge
route/field/verb to the network heads, or correct the claim to "CLI+MCP-only."

### USE-P2-3 · The advertised `collaborate` (git-for-RE) verb is reachable from no head
`ARCHITECTURE.md:59` sells `collaborate`; only `scylla-model/src/lib.rs:188` references it and no head
surfaces it. The collaboration story that sells the platform cannot be invoked by a user. **Advised:**
expose `collaborate` on at least the CLI, or move the claim to "planned." (And fix SEC-P1-1 before you
expose it.)

### USE-P2-4 · MCP has no `info` tool
`crates/scylla-mcp/src/lib.rs:70-102` omits `info`, though CLI/HTTP/GraphQL/RPC all have it. An agent can't
get program name/language/function-count to orient and must infer size from a full `list_functions` dump.
**Advised:** add an `info` MCP tool mirroring `Session::program()`.

### USE-P2-5 · Same concept, different verb name across heads
"One function's detail" is `view` (CLI/RPC), `get_function` (MCP `lib.rs:77`), and `function` (GraphQL
`schema.rs:223`); "list functions" is `functions` everywhere except MCP's `list_functions`. A user moving
between CLI, agent, and GraphQL relearns the vocabulary each time. **Advised:** pick one lexicon and align
the outliers, or publish a verb-mapping table.

### USE-P2-6 · Config sprawl — ~20 `SCYLLA_*` env vars, documented in no single place
`SCYLLA_{RPC,HTTP,GRAPHQL}_TOKEN`, `…_TLS_CERT/KEY`, `SCYLLA_RPC_{MAX_CONN,HANDSHAKE_SEC,TLS_CA,TLS_SNI}`,
`SCYLLA_ENGINE_{WARM,WARM_POOL,UDS,TIMEOUT_SEC,COLD_CONCURRENCY}`, `SCYLLA_WARM_WORKER_SRC`,
`SCYLLA_SCRIPT_DIR` — README/ARCHITECTURE/CONTRIBUTING mention **zero** of them; they live only in
scattered doc-comments. **Advised:** add one "Configuration" table (var, head, default, meaning) to
ARCHITECTURE or `docs/config.md`.

### USE-P2-7 · No schema version field — an incompatible artifact yields garbage or a bare "decode error"
`crates/scylla-schema/schema/model.capnp` (`Program`, lines 6-11) has no version/magic field, and
`LoadError` has only `Decode` (`scylla-schema/src/lib.rs:370`). A user opening an artifact from a
future/older Scylla gets `decode error: …` (or silently defaulted fields) instead of "artifact schema vN,
this build supports vM." **Advised:** add a `schemaVersion` field to `Program`, check it in `load`, return
a distinct `LoadError::Version{found,supported}` with a human message.

### USE-P2-8 · Endpoint scheme mismatch between the docs and the only working recipe
README/`ARCHITECTURE.md:81` show `scylla materialize http://127.0.0.1:50051 <bin>`, but
`run-sandboxed.sh:11` (the sole runnable setup) tells the user `unix:$SOCK_DIR/engine.sock`; the `unix:`
scheme appears only in a code comment (`scylla-engine/src/lib.rs:145`). A user following README against the
sandboxed (network-none) engine cannot connect. **Advised:** document both schemes and make the
ARCHITECTURE example match the sandboxed default.

### USE-P2-9 · ARCHITECTURE claims the warm engine is "not built yet" but it is fully implemented
`ARCHITECTURE.md:93-96` ("a warm co-resident engine is the open perf work"), while
`EngineServer.java:42,275` implements the `WarmEngine` pool (DD-040) and `run-sandboxed.sh:29` documents
`SCYLLA_ENGINE_WARM=1`. A user chasing the ~25s cold-start problem never learns the fix already ships.
**Advised:** move the warm engine from "not built" to a documented, opt-in feature with its env vars (and
see PERF-P2-4 — consider making it the default).

### USE-P3-1 · CLI has no real `--help`/`--version`
`crates/scylla-cli/src/main.rs:43-64` — unrecognized args (incl. `--help`/`-h`) fall through to a usage
string on **stderr** with exit **2**; there is no `--version`. `scylla --help | less` shows nothing;
scripts checking `--version` get an error. **Advised:** treat `-h`/`--help` as success on stdout, add
`--version`.

### USE-P3-2 · Annotate-verb param names and id types diverge
GraphQL retype takes `new_type` (`schema.rs:343`) while HTTP/MCP use `type`; GraphQL ids are `String`
(`schema.rs:338`) while MCP/CLI use integers. A script ported HTTP→GraphQL hits silent mismatches.
**Advised:** standardize on `type` and one id representation, or document the GraphQL-idiom difference.

### USE-P3-3 · MCP `zoom` input schemas don't enumerate valid values
`crates/scylla-mcp/src/lib.rs:73,79` declare `zoom` as bare `{"type":"string"}`; only `list_functions`'s
*description* names `intent|domain|detail`. An LLM guesses an invalid zoom and errors. **Advised:** add
`"enum":["intent","domain","detail"]` to every `zoom` property.

**Positive (no action):** LSP capabilities are honest (all five advertised providers have dispatch arms,
`crates/scylla-lsp/src/lib.rs:40-54`); MCP tool descriptions consistently carry the untrusted-data
framing; TUI keybindings are discoverable via an always-visible footer (`crates/scylla-tui/src/ui.rs:42`).

---

## 6. Scalability

### SCALE-P1-1 · Every server head is single-threaded / single-shared-session — concurrent-analyst ceiling ≈ 1 active request **[verified]**
- `scylla-http`: `for mut request in server.incoming_requests()` with one `&mut session`
  (`crates/scylla-http/src/main.rs:123-125,212` — comment: "the loop is single-threaded … no lock
  needed"). Requests fully serialized.
- `scylla-graphql`: identical single-threaded loop (`crates/scylla-graphql/src/main.rs:61,147`).
- `scylla-rpc-serve`: `Builder::new_current_thread()` + `LocalSet` because capnp caps are `!Send`
  (`crates/scylla-rpc/src/bin/scylla-rpc-serve.rs:112-119`); `SharedSession = Rc<RefCell<Session>>`. All
  connections multiplex on one OS thread.

**Scenario:** 20 analysts on the RPC/HTTP head — a single expensive query (a `/api/diff`, a
`functions?zoom=detail` over 100k functions) blocks *all* others; there is no parallelism. Connection caps
admit 64 (`scylla-serve/src/main.rs:80`, rpc `max_conn` default 64) that then contend on one thread. The
session *is* shared (good — one copy), but access is fully serialized. **Advised:** HTTP/GraphQL are
read-mostly — put `Session` behind `Arc<RwLock<Session>>` and spawn a bounded worker pool (reads take the
read lock in parallel; the three annotation routes take the write lock). For RPC, the `!Send` constraint
forces per-thread `LocalSet`s: shard connections across N runtime threads each holding an `Rc<RefCell<>>`
clone of a shared read-only `Arc<Program>` snapshot, with writes funneled to a single owner via a channel.

### SCALE-P1-2 · The 512 MiB traversal ceiling caps the whole artifact — a legitimately large target fails to load **[verified]**
`crates/scylla-schema/src/lib.rs:335` — `MAX_TRAVERSAL_WORDS = 64 * 1024 * 1024` (~512 MiB), applied to the
whole-artifact reader (`:343`, `:179`). The word-traversal budget tracks total message size, so any
artifact whose content exceeds ~512 MiB refuses to decode. **Scenario:** a Chromium-class 300k-function
target carries per-function `mnemonics`/`trigrams`/`bsim_vector`/`string_refs`/`imports`/`callee_names` —
realistically 1–5 KB/function → a 0.5–1.5 GB artifact. It is under the 1M-function cap but blows the
traversal ceiling → the loader rejects the exact large binary the platform targets. This is an
architectural ceiling, not just a defensive cap, because `from_bytes` materializes the whole message.
**Advised:** scale the traversal ceiling off the actual file length for a trusted local file
(`max(512 MiB, file_len_words · safety)`), keeping the fixed cap only for untrusted/network bytes. Longer
term, move to a segmented/streamed artifact (capnp segments or an on-disk per-function index) so heads
never traverse the whole message to answer one query.

### SCALE-P1-3 · Warm-engine throughput is a hard single-digit ceiling; no horizontal scale-out
`engine-service/.../EngineServer.java:89` `warmPoolSize()` defaults to **1** (cap 16, `:92`), each a full
Ghidra JVM; cold fallback `coldConcurrency()` defaults to **2** (`:138`), gated by a `Semaphore`.
`WarmEngine.materialize` `poll`s and throws "no warm worker free within Ns" when busy; `SCYLLA_ENGINE_
TIMEOUT_SEC` default 300s. **Scenario:** 10 analysts submit firmware simultaneously with the default pool
of 1 → 1 runs, 9 block up to 300s then fail. Even maxed at 16, the 17th queues/times out. One JVM process
— a single-host bottleneck with no horizontal scale-out. **Advised:** raise the default pool to
`min(cores, RAM/worker-footprint)`; add an explicit bounded FIFO with published wait-time/queue-depth in
the response so clients back off; for real multi-analyst load, make `engine-service` horizontally scalable
(a stateless front dispatching to a pool of engine hosts, the warm pool per-host).

### SCALE-P2-1 · Whole-artifact rewrite on every save — no atomic write, no locking → corruption + lost updates
Every persist is a full re-serialize + whole-file overwrite: `scylla-cli/src/main.rs:287,456`
`std::fs::write(out_path, &bytes)` where `bytes = base.to_artifact()`, and `scylla-mcp/src/lib.rs:183`
`std::fs::write(path, &bytes)`. No `flock`, no temp-file+`rename`, no version/CAS check (grep found none).
**Scenario:** two analysts open the same `mathlib.scylla` in two heads, each annotates, each exports → the
second `fs::write` clobbers the first's facts entirely (last-writer-wins whole-file); a crash mid-write
truncates the artifact. Cost also scales — saving one comment on a 500 MB artifact rewrites all 500 MB.
**Advised:** write to `path.tmp` then `std::fs::rename` (atomic on the same filesystem) to prevent
corruption; for collaboration, route concurrent edits through `collaborate` on save under an advisory
`flock`, or adopt an append-only fact log (facts are already durable records, DD-005 — an append log
suits them).

### SCALE-P2-2 · No multi-artifact / corpus capability — every head is exactly one resident `.scylla`
Each head takes one path and loads one `Session` (http `:116`, graphql `:54`, rpc-serve `:39`, serve
`:56`). No index across artifacts, no corpus loader anywhere (grep found none). **Scenario:** an analyst
with 500 `.scylla` files cannot cross-search ("which binary calls `system`") without launching 500
processes; cross-artifact lookup is O(files) full loads. **Advised:** add a corpus-index crate (a
lightweight on-disk index of function name/signature/import → (artifact, StableId) built once per
artifact) plus a head that serves cross-index queries and lazily loads only matching artifacts. This also
unblocks corpus-scale `collaborate`/library-matching.

### SCALE-P2-3 · In-memory decode fully materializes an owned `Program` — resident footprint is a multiple of file size, doubled transiently
`decode_bytes` builds fully-owned `Vec<Function>` with owned `String`s/`Vec`s
(`crates/scylla-schema/src/lib.rs:189,322`); the "zero-copy during decode" comment (`:175`) notwithstanding,
the result is a fully materialized native graph, and during load both the input `bytes` and the owned
`Program` are live. **Scenario:** a 200 MB artifact → a 400 MB–1 GB decoded `Program`, peak-during-load ≈
file + decoded together; `scylla-serve` additionally `Box::leak`s the raw bytes for process life
(`:77-78`), and the wasm head decodes the *entire* artifact inside the browser tab — a tab memory ceiling.
**Advised:** offer a borrowed/lazy `Session` keeping the capnp reader over an `mmap`ed file, projecting
`FunctionView`s on demand (capnp is designed for this) — the read-only heads never need the full owned
`Program`; paginate/stream the wasm function tables rather than shipping the whole artifact to the browser.

### SCALE-P2-4 · `collaborate` existing-fact lookup is O(F_incoming · F_base)
`crates/scylla-merge/src/lib.rs:1083` inside `for fact in &incoming.facts` (`:1071`) does
`base.facts.iter().find(...)` — a full scan per incoming fact. Merging two 100k-fact artifacts → 10¹⁰
comparisons. Facts are usually fewer than functions, so lower severity, but it grows quadratically as
teams accumulate annotations. **Advised:** pre-build a `HashMap<(target, kind_discriminant), &UserFact>`
over `base.facts` once → O(1) lookup.

### SCALE-P3-1 · 1,000,000-function/-fact hard decode caps reject a very large corpus binary outright
`crates/scylla-schema/src/lib.rs:17-19` — `MAX_DECODED_FUNCTIONS`/`MAX_DECODED_FACTS`/
`MAX_DECODED_LIST_ITEMS = 1_000_000`, enforced via `checked_list_len` (`:45`). Chromium (~300k) is under
it, but a monolithic firmware/AOSP-style image or a merged corpus artifact can exceed 1M functions.
Deliberate anti-abuse caps, but they reject rather than degrade. **Advised:** keep them as bounds but make
them configurable and raise the function/fact ceiling to 8–16M for trusted local files — in step with
SCALE-P1-2 (traversal) and SCALE-P2-3 (memory), which are the real constraints.

### SCALE-P3-2 · 64 KiB string truncation can silently collide long symbols (untrusted path only)
`crates/scylla-schema/src/lib.rs:339` `MAX_STRING_LEN = 64 * 1024`; on the bounded-load path over-long
names are truncated. Heavily-templated C++/Rust mangled symbols can exceed 64 KiB pathologically →
truncation could make two symbols share a display name. Deliberate defense; the default `from_bytes` uses
`bounded=false` (`:167`) so trusted local loads keep full strings. **Advised:** leave as-is for the hostile
path; document that the cap applies only to the untrusted-load path.

### SCALE-P3-3 · No multi-user server primitives — the growth path is blocked by three things at once
`Principal` defaults to a hardcoded `"local"` (`crates/scylla-port/src/lib.rs:121`) and heads gate on a
single shared bearer token, so there is no per-user authz or attribution across a team; heads bind one
file path at startup (no artifact store); and SCALE-P1-1 (single shared mutable session) + SCALE-P2-1
(whole-file clobber writes) actively prevent concurrent editing. **Advised path:** a session/artifact-store
layer (per-user sessions over an `Arc<Program>` snapshot store), writes as an append-only per-user fact
log merged via `collaborate`, and per-principal auth — the `Principal`/`author` seams (DD-035) and the
`collaborate`/confidence machinery already exist to build on (once SEC-P1-1 is fixed).

---

## 7. Cross-cutting recommendations (fix the root, close many findings)

1. **Cache features once, then bucket — the O(N²) matcher.** Hoisting per-function `anchor_set`/mnemonic/
   trigram/bsim caches + norms out of the fixpoint loop and adding LSH candidate-bucketing closes
   PERF-P1-1, PERF-P2-1, SCALE-P2-4 and makes SCALE-P1-2/-P1-3 tractable at firmware scale. This is the
   highest-leverage single change in the review.
2. **Make the serving model concurrent and the writes safe.** `Arc<RwLock<Session>>` + a bounded worker
   pool (HTTP/GraphQL) and sharded per-thread `LocalSet`s over an `Arc<Program>` snapshot (RPC), plus
   temp-file+`rename` atomic writes and an advisory `flock`, closes SCALE-P1-1 and SCALE-P2-1 and unblocks
   the multi-analyst story (SCALE-P3-3). Read-mostly access behind a borrowed `Session` (SCALE-P2-3) drops
   the per-head memory ceiling at the same time.
3. **Stop trusting untrusted data's self-asserted trust.** Scope confidence-resolution to
   locally-originated facts and treat cross-provenance disagreements as conflicts unconditionally
   (SEC-P1-1); neutralize the envelope case-insensitively (SEC-P2-1); make DD-034 a code-enforced default,
   not an ops convention (SEC-P2-2/-P2-4). These are the trust-boundary roots.
4. **Add a supply-chain gate and pin the release lane.** A `deny.toml` + `cargo deny check` CI job, an
   upgrade off `tiny_http`'s vulnerable `rustls`/`ring`, and SHA-pinned actions in `release.yml` close
   SEC-P2-5 and keep the signing guarantee honest.
5. **Make the docs match the code, or the code match the docs — pick one.** A "same verbs" claim the CLI
   violates (USE-P2-1), a `merge` on 2/9 heads (USE-P2-2), a `collaborate` on 0 heads (USE-P2-3), a
   "not built yet" warm engine that shipped (USE-P2-9), and a build that fails on undocumented tools
   (USE-P1-1) are all one root: **the documentation is not generated from, or checked against, a single
   source of truth.** Fix onboarding first (USE-P1-1/-P1-2/-P1-3), then reconcile the verb matrix.
6. **Surface what the loader quarantines.** Wiring `load_report()` into every head (USE-P1-3) is a
   one-afternoon change that restores the platform's headline "never silently wrong" promise — which,
   ironically, the *loader* keeps and the *heads* break.

---

## 8. Tracking follow-up — completed 2026-07-24

- All 46 findings are present in `BACKLOG.md`.
- Every finding has a Codeberg issue (#119–#164) and a GitHub representation (#4, #6, #7, #9, and
  #10–#49), linked from both the backlog and the remediation-status table above.
- This review is now tracked on `fix/review-backlog-3-9`; its original evidence remains anchored to
  `6fb100f`, while the status table records remediation through `1012dcd`.

---

*Generated by a four-reviewer parallel architecture pass with direct source verification of every P0/P1
claim and a clean-toolchain clippy/test/audit ground-truth run. Line numbers are against `6fb100f`;
re-check after any edit. Pedantry is the point — hold the code to the standard it already sets for itself.*

*Proudly Made in Nebraska. Go Big Red! 🌽 <https://xkcd.com/2347/>*
