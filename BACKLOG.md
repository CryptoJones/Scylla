# Scylla — Backlog

Tracked "later / someday" items that aren't on the current sprint path
([SprintPlanning.md](SprintPlanning.md)) but shouldn't be lost.

## Docs

- [ ] **Revisit the proposed architecture diagram** (`docs/proposed-scylla-architecture.drawio`).
  It's readable and hexagonal now, but the layout could be tightened — port placement on the
  rim, edge routing, balance of the driving/driven sides. A polish pass, not a redo.

## Possible future adapters (the whole point of the hexagon)

- [x] **Evaluate the x64dbg / Scylla dynamic-analysis ecosystem as a future *producer* adapter.**
  Done — [docs/eval-dynamic-analysis-producer.md](../docs/eval-dynamic-analysis-producer.md).
  Verdict: a strong *eventual* adapter (it's exactly what the narrow waist absorbs without a
  rewrite — a second producer feeding the same model), **deliberately deferred**: executing hostile
  code is a categorically harder containment tier than the DD-034 parser sandbox, the static+dynamic
  merge is confidence/coverage-asymmetric (a real `collaborate` extension), and the static path
  (decompile, warm engine, cross-arch) isn't finished. No-regret groundwork noted: first-class
  producer **provenance** (DD-007) + coverage-aware `collaborate` (DD-027). First real step: a
  narrow seam prototype (ingest one runtime artifact, merge vs the static model) before betting on
  the harness.

## Re-anchoring recovery

- [x] **Add a structural fingerprint to `scylla-model::Function`.** `Function.fingerprint` is the
  FNV-1a hash of the mnemonic histogram (computed in `scylla-ingest` from the snapshot's
  `mnemonics`), folded into `scylla-merge`'s signature. It disambiguates coarse-signature
  collisions, lifting the **DD-038 aarch64 edit floor 40% → 80%** with `WRONG=0` held by
  construction (a richer signature only adds *unique* matches; a fingerprint collision is
  ambiguous → flagged, never wrong). Two follow-ups it opens:
  - [x] **Carry the mnemonic histogram over the engine.proto wire.** `FunctionChunk.mnemonics @6`
    carries the instruction stream raw; `EngineServer` populates it from `dump_model.java`, and
    `chunk_to_function` hashes it with the SAME `scylla_model::mnemonic_fingerprint` the snapshot
    path uses. Verified live: a gRPC-materialized mathlib artifact has 13/13 non-zero fingerprints
    that MATCH the snapshot path's exactly (0 mismatch) — the two producers re-anchor against each
    other. The engine never hashes; one hash, one place.
  - [x] **Fuzzy / cross-build recovery for the hard classes.** `scylla-merge` now runs an exact
    pass then a **fuzzy second pass** — cosine over the stored mnemonic histogram + structural
    closeness, accepted only above a threshold (`FUZZY_THRESHOLD`) AND with a runner-up margin
    (`FUZZY_MARGIN`). Lifts **both DD-038 edit classes to 100%** (the floors are ratcheted there)
    and recovers some recompile (x86 O0→O2: 0%→20%). `WRONG=0` held throughout: exact is
    unique-match, fuzzy is threshold + margin ("never guess a near-tie").
  - [x] **Cross-architecture re-anchoring via arch-independent anchors (DD-041).** Cosine over the
    mnemonic mix is ~0 across ISAs (x86-64 vs aarch64 share no instructions), so the engine now
    extracts the features that *do* survive a cross-ISA recompile — **referenced string literals +
    imported call names** (`Function.string_refs` / `imports`, over both the snapshot path and the
    gRPC wire) — and `scylla-merge` runs an **anchor pass** (Jaccard over that set, unique best +
    high threshold + wide margin) between the exact and fuzzy passes. Cross-arch goes **0 → recovers
    the string/import-bearing function (`main`)** in both mathlib and strutil (gate floors ratcheted
    to lock it in). Claiming those high-confidence matches first surfaced a latent fuzzy false
    positive (an inlined-away function latching onto a CRT stub via common small-function mnemonics),
    fixed with **reciprocal-best matching** (a fuzzy match must be mutual). `WRONG=0` held; edit
    classes still 100%. Grounded in the cross-ISA diffing literature (BinDiff/SIGMADIFF anchor on
    strings+imports) via deep research, not guessed. The string/import extraction is **duplicated**
    between `dump_model.java` and `ScyllaWarmWorker.java` (kept in sync by hand) — consolidation is a
    tracked wart.
  - [x] **Call-graph propagation from the anchors (DD-041).** A fourth `scylla-merge` pass spreads
    confirmed matches along the **call graph**: a function the other passes can't place is matched by
    its position relative to already-matched functions, using a deliberately NON-structural
    discriminator (self-recursion + matched-neighbour agreement — size/bb *mis*-match cross-arch, so
    they're excluded). Recovers `fib` (the unique self-recursive callee of `main`) **both cross-arch
    and cross-opt** — mathlib O0→O2 and x86→aarch64 each go **20%→40%**; symmetric leaves
    (gcd/factorial/sum_to) stay flagged. `WRONG=0` held, incl. the subtle rule that a lone surviving
    candidate must beat the *generic-neighbour baseline* ("only option left" ≠ evidence — the true
    match may be inlined away). Gate floors ratcheted on the recompile + cross-arch classes. **Next
    lever:** the heavier Ghidra Version Tracking integration (for functions with neither
    strings/imports nor a distinguishing graph position).

## Engine-as-service (DD-040)

- [x] **Warm co-resident engine (perf) — BUILT (DD-040).** Materialize used to cold-launch
  `analyzeHeadless` per call (~6s host / ~25s container, almost all fixed JVM+Ghidra init). Now,
  opt-in via `SCYLLA_ENGINE_WARM`, the service stands up ONE resident GayHydra JVM at startup that
  inits the application + SLEIGH + decompiler once, then imports + analyzes each binary in-process
  — only the first call pays cold init, the rest are ~2s. The worker (`engine-service/warm-worker/
  ScyllaWarmWorker.java`) is a **standalone Java program, NOT a Ghidra script**: the OSGi script
  compiler can't see `ProgramLoader` / `AutoAnalysisManager`, so the warm path must compile against
  the dist directly (`EngineServer.WarmEngine` runs `javac` at startup, exactly like the de-risk
  spike — no build-coupling to the ~890MB dist). Requests are **serialized** (Ghidra analysis isn't
  thread-safe per program); a wedged/failed call kills the worker and the RPC **falls back to the
  cold subprocess** (the subprocess is the fallback behind the same RPC, DD-040). Proven live:
  warm artifact is **byte-identical** to the cold one (mathlib 13 functions, 1072 bytes), at
  **~3x** the speed (6.2s cold → 1.7–2.0s warm, host), end to end through gRPC + the `scylla` CLI +
  the Cap'n Proto artifact. The classloader-coexistence **spike** ([spike/warm-engine/](spike/warm-engine/))
  proved grpc-netty-shaded + in-process `Application.initializeApplication` coexist in ONE JVM
  (~700ms) — the DD-040 nightmare didn't happen. Default OFF: cold-only stays the proven,
  dependency-light path; warm is opt-in. Follow-up: a **pool of warm contexts** (not just one) for
  concurrent materialize, and consolidating the dump extraction shared with `dump_model.java`
  (currently duplicated — the cold script can't link the standalone worker's class).
- [x] **Wire the Rust core to the engine-port gRPC stream.** The new `scylla` CLI
  (`crates/scylla-cli`) is the composition root: `scylla materialize <endpoint> <binary>
  <out.scylla>` drives the engine-service over gRPC and consumes the `Materialize` stream straight
  into the canonical artifact — id mint + callee-address resolution happen core-side in
  `scylla_engine::assemble`. No intermediate snapshot file, no `materialize.sh` in the loop. Proven
  end to end: binary → gRPC → `.scylla` (13 mathlib functions, 952 bytes), then loaded back through
  the MCP head. The offline snapshot path (`scylla-ingest` + `materialize.sh`) stays for dev /
  corpus work without a running service. The composition lives in a CLI crate so neither the port
  adapter nor the WASM consume-side core carries the other's dependencies (DD-002).
- [x] **Config-ify the engine-service.** `dump_model.java` now lives in `engine-service/scripts/`
  (single source of truth) and ships in the install/image; `EngineServer` resolves it relative to
  its own jar, so the service no longer reaches into `prototype/harness` at run time and the
  sandbox runner drops the script mount. `GHIDRA_DIST` is now a REQUIRED, fail-fast config (no
  laptop-specific default), validated at startup; `SCYLLA_SCRIPT_DIR` defaults to the shipped
  scripts dir and is override-only.

## Security

- [x] **Full no-egress lockdown for the engine sandbox (DD-034 / GAP-1).** The container now runs
  with `--network none` — no interfaces, no published port, no route out — and gRPC rides a
  **bind-mounted Unix socket**: `EngineServer` listens on a UDS via the grpc-netty epoll transport
  when `SCYLLA_ENGINE_UDS` is set, and the tonic client dials a `unix:/path` endpoint via a custom
  connector. A hostile binary literally cannot phone home. Proven live: `--network none` +
  `scylla materialize unix:…/engine.sock` → 13 functions, no network at all. Full DD-034: no host
  FS, no privilege, no core access, **no egress**.
- [x] **Threat-model the seams.** Done — [THREAT-MODEL.md](THREAT-MODEL.md): a seam-by-seam pass
  (S1 binary→engine, S2 engine→core, S3 artifact→core, S4 core→agent, S5 agent→core) over the
  three untrusted inputs, citing the mitigations and naming the residual gaps. It found four, the
  four items below (GAP-4 is the priority — it's the *current* threat).
- [x] **GAP-4 — the MCP head now delimits untrusted analysis content (DD-035).** Every tool result
  carrying binary-derived text (`list_functions`/`get_function`/`callers`) is wrapped in an
  explicit `<untrusted-data>` envelope with a never-instructions preamble; the contract is also
  stated in the tool descriptions. Default-untrusted — only the head's own status acks
  (`STATUS_ONLY_TOOLS` = rename/comment) and typed errors pass through unwrapped, so a future read
  tool (e.g. `decompile`) is marked automatically. Regression-tested.
- [x] **GAP-3 — the core now bounds the engine `Materialize` stream.** `materialize()` caps the
  cumulative function count (`MAX_FUNCTIONS`) and instruction count (`MAX_TOTAL_MNEMONICS`) and
  fails closed with a typed error past either — a compromised/buggy engine can no longer OOM the
  trusted core (each message is already tonic-size-bounded; these cap the cumulative stream). The
  live-stream analogue of the DD-036 artifact caps. Cap check is unit-tested.
- [x] **GAP-2 — wall-clock timeout on the engine subprocess (DD-034).** `EngineServer` now drains
  stdout off-thread and bounds the wait with `p.waitFor(timeoutSeconds(), SECONDS)`
  (`SCYLLA_ENGINE_TIMEOUT_SEC`, default 300); on timeout it `destroyForcibly()`s the subprocess and
  returns `DEADLINE_EXCEEDED`. A binary engineered to hang `analyzeHeadless` can no longer tie up
  the engine slot. Verified live (a 1s budget kills a real run; the default budget passes).
- [x] **Automate release signing (cosign, DD-029).** `.github/workflows/release.yml` signs release
  artifacts on a version tag with **Sigstore KEYLESS cosign** — no key (the GitHub Actions OIDC
  identity via Fulcio + the Rekor transparency log). It builds the `scylla` CLI + checksums, signs
  them (`cosign sign-blob --bundle`), and attaches binaries + bundles to the release. The
  `sign-engine-image` job also builds the **engine-service sandbox image** (the security-critical
  artifact), pushes it to `ghcr.io`, and keyless-signs the pushed digest (`cosign sign`). Both
  verified per SECURITY.md.
