# Scylla — Backlog

Tracked "later / someday" items that aren't on the current sprint path
([SprintPlanning.md](SprintPlanning.md)) but shouldn't be lost.

## Docs

- [ ] **Revisit the proposed architecture diagram** (`docs/proposed-scylla-architecture.drawio`).
  It's readable and hexagonal now, but the layout could be tightened — port placement on the
  rim, edge routing, balance of the driving/driven sides. A polish pass, not a redo.

## Ports

- [x] **Cap'n Proto promise-pipelining RPC surface for the client port (DD-002) — BUILT & SHIPPED
  (2026-06-23, authorized — the deferral lifted): `crates/scylla-rpc`.** The production `interface`
  (`Session` info/functions/function, `Function` view/callers/rename/retype/comment) + `capnp-rpc`
  server impls over `scylla_port::Session`, the network transport (`scylla-rpc-serve` over TCP), and
  the **remote head** (`scylla-rpc-connect`) — a consumer not co-located with the core, navigating by
  promise-pipelining. Verified end-to-end cross-process over real TCP (`tests/remote.rs`), in-process
  two-party (lib tests: pipelined navigation, rename round-trip, DD-021 blank-name rejection). The
  port needed ZERO changes. Original deferral note (now historical):  Today the
  client port is served **in-process** — the heads drive `scylla_port::Session` directly (the MCP
  head marshals JSON-RPC ↔ port; the non-MCP client calls `Session` straight), and the only Cap'n
  Proto in the tree is the model-artifact *persistence* schema (`model.capnp` — data `struct`s, no
  `interface`; no `capnp-rpc` dependency). The promise-pipelining **RPC wire** that DD-002's schema
  choice anticipated is deferred until a **remote / networked head** actually needs it (a head not
  co-located with the core). Build then: add an `interface` to the schema + a `capnp-rpc` server
  projecting the port, behind the existing in-process surface. **Shape validated** by
  `spike/rpc-shape` (2026-06-22, GO) — the port projects 1:1 to a capnp RPC interface and
  pipelines with no port change; that spike is a usable seed for the real `interface`.

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
  - [x] **Seam spike — DONE, GO (2026-06-23): [spike/dynamic-analysis/](spike/dynamic-analysis/).**
    A synthetic *resolved IAT* (what a dynamic IAT-rebuilder emits for a packed sample — NOTHING is
    executed) merges into the static `mathlib` model **by `StableId`**: the 6 entries land +5
    dynamic-only imports across 5 functions, 1 already-known (deduped), **0 unmatched** — the narrow
    waist absorbed a second producer with no rewrite. And because `Function.imports` is a DD-041
    cross-arch **anchor** input, a dynamic IAT rebuild *lifts re-anchoring* on packed/stripped
    samples where static imports go to 0. Seam proven (as DD-004 / DD-040 were). Productionize behind
    DD-007 provenance + DD-027 coverage-aware collaborate; the **execution-containment harness stays
    DEFERRED** with its own threat model (do NOT weaken DD-034 to prepare for it). Full writeup +
    `run-spike.sh` in the spike dir.
  - [x] **Harness DE-RISK — DONE (2026-06-24, design only): [spike/dynamic-analysis/HARNESS-THREAT-MODEL.md](spike/dynamic-analysis/HARNESS-THREAT-MODEL.md).**
    The "own threat model" the eval required, written before any execution: the new seam **S6 — sample
    → execution harness** (executing attacker code, categorically above the DD-034 *parser* sandbox),
    the containment tier (VM-grade/microVM, ephemeral, hard no-egress, no host FS, resource+wall-clock
    bounds, one-way untrusted observation channel), and the OPEN gaps that gate the build (GAP-5
    sandbox escape, GAP-6 observation-channel injection, GAP-7 resource exhaustion, GAP-8 evasion,
    GAP-9 contamination). A NON-EXECUTING prototype (`src/harness.rs`: a `DynamicHarness` trait +
    `RecordedHarness` that replays a recorded trace) proves the producer interface + the
    observe→DD-007-`dynamic`-provenance flow end-to-end, executing nothing. **The real `MicroVmHarness`
    stays DEFERRED** until the containment tier is built + pen-tested against GAP-5..9. Still gated.
  - [x] **Harness BUILD PLAN — DONE (2026-06-24, plan only): [spike/dynamic-analysis/HARNESS-BUILD-PLAN.md](spike/dynamic-analysis/HARNESS-BUILD-PLAN.md).**
    The staged engineering design for *building* the harness, gated milestone-by-milestone: **M1**
    containment tier (microVM/Firecracker, red-teamed for GAP-5/7) → **M2** one-way observation channel
    (GAP-6, DD-036 caps) → **M3** in-guest observer (Linux ptrace/Frida/QEMU IAT-rebuilder) → **M4**
    `MicroVmHarness: DynamicHarness` producer, end-to-end on BENIGN samples (WRONG=0 held) → **M5**
    widen to hostile samples on an isolated node + external pen-test. Cost concentrated in M1 + M5
    (multi-week security engineering, not a feature); M2–M4 mechanical once M1 stands. **No hostile
    execution before M5; build only on an explicit go, one milestone at a time.** The plan exists so
    the work is schedulable; building it remains DEFERRED.
    - [x] **M1 containment tier — FIRST CUT DONE (2026-06-24): [spike/dynamic-analysis/harness-m1/](spike/dynamic-analysis/harness-m1/).**
      `m1-microvm.sh` stands up an EPHEMERAL, NO-EGRESS (`-nic none`), 256M-capped, kill-switched
      (`timeout`) QEMU `microvm`+KVM sandbox that runs a BENIGN payload and is destroyed. Verified on
      ronin28 (VT-x + `/dev/kvm`, user in `kvm` group → no sudo to run; QEMU installed): the guest
      executed (`M1_GUEST_RAN ok`), had zero network interfaces, and powered off (qemu rc=0). Proves
      execution + containment + ephemeral teardown on a cooperative guest. **GATE — now PASSED
      (2026-06-24, see next bullet);** M5 should still migrate the tier to Firecracker (smaller attack
      surface). No hostile code run; no Scylla integration yet. Report: harness-m1/M1-REPORT.md.
    - [x] **M1 GATE red-team — PASS (2026-06-24): [harness-m1/m1-redteam.sh](spike/dynamic-analysis/harness-m1/m1-redteam.sh).**
      Boots SYNTHETIC hostile guests that attack every containment knob and asserts FROM THE HOST that
      nothing escaped — **16/16 across 5 scenarios**: GAP-5 escape (no NIC/egress, no block devices,
      `vda`/`9p`/`virtiofs` mounts all blocked, no vsock, host canary untouched), GAP-7 (CPU-spinner +
      fork-bomb reaped by the kill-switch `rc=124` with the host responsive — heartbeat gap 0.31s, host
      proc table flat 466→465; memory balloon OOM-killed INSIDE the VM, host RAM drop just 171MB),
      GAP-9 ephemeral (no cross-run persistence). Closes GAP-7/GAP-9 and GAP-5 for the **configured
      surface** on synthetic attacks; the QEMU-device-0-day residual + real malware is **M5**
      (Firecracker + external pen-test). **M2 is now UNBLOCKED.** Report: harness-m1/M1-REDTEAM-REPORT.md.
    - [x] **M2 one-way observation channel — DONE, GAP-6 fuzz PASS (2026-06-24): [harness-m2/](spike/dynamic-analysis/harness-m2/) + [src/channel.rs](spike/dynamic-analysis/src/channel.rs).**
      The channel out of the no-egress tier is the guest's **serial console** (one-way, no new device);
      the host reader (`channel.rs`) treats it like a stranger's `.scylla` — DD-036 caps on every
      dimension, validate-then-quarantine, never `eval`, DD-035-sanitized on display. **GAP-6 gate:**
      `cargo test` `channel::gap6` — **19 cases** (oversized / no-newline-gigabyte / too-many-lines /
      bad-base64 / len+checksum-mismatch / invalid + 5000-deep-nested JSON / >4096-records / bad-fields
      / control-bytes) each a bounded rejection, **no panic/hang/OOM**. Live end-to-end on the real
      microVM (`harness-m2/m2-channel.sh`): a trace read off serial through console noise; a corrupted
      channel quarantined. **M3 (in-guest observer) is now UNBLOCKED.** Report: harness-m2/M2-REPORT.md.
    - [x] **M3 in-guest observer — DONE, benign-sample gate PASS (2026-06-24): [harness-m3/](spike/dynamic-analysis/harness-m3/).**
      Inside the M1 tier, runs a benign dynamic sample under the glibc loader's `LD_DEBUG=bindings` +
      `LD_BIND_NOW` — the loader resolves + logs every import, reconstructing the **resolved IAT** at
      runtime (what a dynamic IAT-rebuilder emits). The observer frames it (`m3-frame.c`, base64+FNV
      matching `channel.rs`) onto the **M2 serial channel**; the host reads it back through the bounded
      validator and confirms the ground-truth imports (`getpid`/`puts`/`snprintf`, +8 libc) — **PASS**,
      loader-deterministic, within budget. So: execute-in-sandbox → observe → channel → validate, end
      to end. **Honest limit:** `LD_DEBUG` needs a *cooperative* sample; the general observer for
      packed/anti-analysis malware is **ptrace / QEMU-user trace**, which rides with **M5**. GAP-8
      (evasion) stays open → DD-007/DD-027 confidence weighting in M4. **M4 is now UNBLOCKED.** Report:
      harness-m3/M3-REPORT.md.

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
    strings+imports) via deep research, not guessed.
  - [x] **Consolidate the extraction (DD-041).** The program→snapshot-JSON extraction is now a single
    `ScyllaModel.toJson` (in `engine-service/scripts/ScyllaModel.java`), called by BOTH producers:
    `dump_model.java` (the cold/offline Ghidra script) and `ScyllaWarmWorker.java` (the warm
    standalone worker). The earlier "OSGi can't share" fear was about the *import+analyze* classes
    (`ProgramLoader`/`AutoAnalysisManager`) — the extraction touches none of those, only the public
    `ghidra.program.model.*` API a script may use, so the OSGi script compiler resolves it as a
    scriptPath helper (verified). The engine-service compiles `ScyllaModel` alongside the worker.
    Cold AND warm outputs proven byte-identical to before. No more by-hand sync.
  - [x] **Call-graph propagation from the anchors (DD-041).** A fourth `scylla-merge` pass spreads
    confirmed matches along the **call graph**: a function the other passes can't place is matched by
    its position relative to already-matched functions, using a deliberately NON-structural
    discriminator (self-recursion + matched-neighbour agreement — size/bb *mis*-match cross-arch, so
    they're excluded). Recovers `fib` (the unique self-recursive callee of `main`) **both cross-arch
    and cross-opt** — mathlib O0→O2 and x86→aarch64 each go **20%→40%**; symmetric leaves
    (gcd/factorial/sum_to) stay flagged. `WRONG=0` held, incl. the subtle rule that a lone surviving
    candidate must beat the *generic-neighbour baseline* ("only option left" ≠ evidence — the true
    match may be inlined away). Gate floors ratcheted on the recompile + cross-arch classes.
  - [x] **Go / 32-bit corpus validation (DD-041).** Pushed the four-pass matcher onto two new axes
    to find where it breaks ([docs/corpus-findings.md](../docs/corpus-findings.md)). **32-bit (i386)**:
    same C source, so it's gated in Tier-0 — the matcher generalizes with ZERO changes (edit-32
    100%, recompile-32 + cross-arch 64→32 recover main+fib at 40%, all WRONG=0; floors ratcheted).
    **Go** (Tier-1, generated on demand — ~1.5MB/1900-func snapshots are too big to commit): two
    findings — (1) **scale robustness**, WRONG=0 across ~3000 functions (recovers main+fib in the
    runtime-function haystack, no false positives); (2) **the anchor is C-centric** — Go cross-arch
    recovers 0 because Go strings aren't NUL-terminated C strings and `fmt.Printf` isn't a dynamic
    import, so the string/import anchor never fires. The matcher fails *closed* (flag, never guess).
    This is the concrete motivation for a Go-aware producer and/or a cross-arch similarity engine.
  - [x] **Ghidra Version Tracking — evaluated, NO-GO (DD-042).** De-risk spike
    ([spike/vt/](spike/vt/)) before a multi-PR build. VT runs headlessly (with two gotchas, both
    documented), but its correlators are exact instruction/byte/mnemonic matchers built for
    *version-to-version patch diffing* (seed the byte-identical bulk, propagate to the few changed) —
    the OPPOSITE of Scylla's hard cases. Measured (mathlib, WRONG=0): recompile O0→O2 VT recovers **0**
    user functions vs the four-pass matcher's 40%; cross-arch VT recovers **0** (no shared
    bytes/instructions → no seeds) vs 40%. VT would underperform the matcher we already ship on the
    cases that matter. **Real next levers:** a **Go-aware producer** (de-risked, GO — see below) and
    **BSim** (`VersionTrackingBSim`, LSH over decompiler p-code feature vectors — ISA-abstracting; the
    heavier, still-un-de-risked alternative for the symmetric C leaves + cross-arch). VT *is* right for
    a future near-identical patch-diffing use case, not this gap.
  - [x] **Go-aware producer — BUILT (DD-043).** The DD-041 cross-arch anchor was C-centric (Go
    recovers 0 cross-arch). Fixed via **callee NAMES**: `ScyllaModel` now emits each function's
    package-qualified callee names (`Function.callee_names`), carried over the gRPC wire + Cap'n Proto
    and folded into the matcher's `anchor_set`. Ghidra recovers Go names from `.gopclntab` even when
    STRIPPED, and the callee-name set is identical across ISAs (Jaccard 1.0). The **dotted-name
    filter** (`'.'` present, not leading-`_`, no `::`, not `FUN_*`) is the honesty guard: it captures
    Go's `importpath.Func` names — which survive stripping — and EXCLUDES C's bare local names (which
    don't), so the unstripped-C gate can't cheat. Verified: C callee_names are empty across all 11
    gate classes (floors UNCHANGED, WRONG=0); the Rust matcher anchors on callee-names alone with
    cosine=0 (unit-tested); the producer emits 8 qualified names for Go `main.main`; the de-risk
    measured cross-arch recovery 0 → 2/4. **Caveat:** Ghidra's Go support lags the release — Go 1.26
    crashes `GolangSymbolAnalyzer`, Go 1.22 works; viable for supported Go versions. Go gating stays
    out-of-Tier-0 (snapshots ~1.5MB); the spike (`spike/go-producer/run-spike.sh`) is the Go
    regression check. **BSim** remains the heavier, un-de-risked lever for the symmetric *C* leaves.
  - [x] **BSim decompiler-signature similarity — de-risked, GO (DD-044).** The last un-de-risked
    cross-arch lever, aimed at the symmetric arithmetic leaves the matcher flags. De-risk spike
    ([spike/bsim/](spike/bsim/)), **DB-free** (the `DecompInterface.generateSignatures` →
    `WeightedLSHCosineVectorFactory` path, no BSim database): BSim's p-code feature vectors match
    cross-arch (x86-64↔aarch64) where mnemonic cosine is 0 — `factorial` and `sum_to` each hit their
    twin at cosine **1.000** (signif ~22, reciprocal) and stay distinct despite being one p-code
    opcode apart (margin 0.289); cross-arch `mathlib` 40%→**80%** (main+fib+factorial+sum_to). `gcd`
    (modulo: x86 `DIV` vs aarch64 `SDIV`+`MSUB`) decompiles to different p-code per ISA (self-sim
    0.120) and **flags fail-closed** — every current signal misses it, honest coverage. Integration
    MUST gate on **sim≥0.7 + reciprocal-best + significance**, never raw argmax (which emits a
    spurious `gcd→factorial`) — the existing pass-3 discipline, with reciprocal-best load-bearing
    (`factorial→sum_to`=0.711 clears a bare 0.7 floor). `./spike/bsim/run-spike.sh` is the regression
    artifact.
  - [x] **BSim cross-arch re-anchoring pass — BUILT (DD-044, 3 slices).** Matcher: `scylla-merge`
    Pass 4 (BSIM) — weighted cosine over `Function.bsim_vector`, gated sim≥0.7 + reciprocal-best +
    min-feature significance proxy, no-op on empty vectors. Wire: `bsim_vector` rides `model.capnp` +
    `engine.proto` + `scylla-ingest` + `scylla-schema` round-trip. Producer: a standalone `ScyllaBsim`
    extractor used by the warm worker (kept OUT of the OSGi-shared `ScyllaModel`, which only
    serializes it; cold path degrades to empty); `EngineServer` compiles it + parses it into the gRPC
    chunk. Proven end-to-end on real mathlib: `factorial`+`sum_to` re-anchor x86-64↔aarch64, `gcd`
    (modulo) stays flagged, **cross-arch 40%→80%, WRONG=0** (gate floor ratcheted). strutil/i386 + the
    cold path carry no vectors yet (clean no-op) — widening that is future work.
  - [x] **BSim cross-arch widened to the strutil 64-bit corpus (DD-044 follow-on).** Regenerated
    `strutil.{x86-64,aarch64}.O0` snapshots with `bsim_vector`; BSim recovers all of strutil's string
    leaves (`my_strlen`/`my_reverse`/`count_vowels`) cross-arch — **25%→100%, WRONG=0**, floor
    ratcheted to 1.0.
  - [x] **i386 cross-*width* BSim — de-risked, NO-GO (DD-044).** 32↔64 collapses the symmetric leaves
    (factorial↔sum_to margin 0.000, vs 0.289 cross-arch); gated only gcd+fib match (2/5), and the
    producer's per-arch weights would make live worse than the spike's best-case cross-width weights.
    Marginal gain for real complexity (the matcher already does main+fib at 40%) → not worth it. Only
    open BSim lever left: the cold `dump_model` path (OSGi can't see BSim) — a clean no-op today.

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
  dependency-light path; warm is opt-in. The dump extraction is now shared with `dump_model.java`
  via `ScyllaModel` (see the re-anchoring section — DD-041 consolidation).
- [x] **Pool of warm contexts for concurrent materialize (DD-040).** The warm engine is now a POOL:
  `SCYLLA_ENGINE_WARM_POOL=N` (default 1) spawns N resident workers, and `materialize` checks one out
  of a blocking queue, uses it, and returns it — so up to N binaries analyze CONCURRENTLY. Separate
  workers analyze separate programs, which is safe (Ghidra's thread-safety hazard is only *within* a
  single program's analysis). The worker + shared `ScyllaModel` compile ONCE; a wedged/killed worker
  is dropped from the pool (not returned), and if the pool drains the RPC falls back to cold. Each
  worker is a full Ghidra JVM, so N is RAM-bound (capped at 16). Proven: pool=2 warms 2 workers and
  serves 2 concurrent `materialize` calls. The sandbox runner passes `SCYLLA_ENGINE_WARM_POOL`
  through with a memory-sizing note.
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
