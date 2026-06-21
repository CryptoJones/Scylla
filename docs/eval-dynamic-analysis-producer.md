# Evaluation — a dynamic-analysis producer behind the engine port

**Question.** Should Scylla grow a second producer — x64dbg + Scylla (import reconstruction),
debugger dumps, unpacked-at-runtime images — feeding runtime-resolved facts into the same model
artifact through the engine / binary-source ports (DD-009 / DD-018)?

**Verdict up front: a strong *eventual* adapter, deliberately deferred.** It is exactly the kind
of thing the hexagon exists to absorb later without a rewrite — which is the reason *not* to build
it now. Waiting incurs no architectural debt; building it now means standing up an execution-grade
sandbox and a provenance model the static path doesn't yet need. Do the static path justice first.

## What dynamic analysis actually buys (that static can't)

Static analysis (GayHydra) reasons about the bytes as written. A running process reveals what the
bytes *do*:

- **Real imports.** Packed/obfuscated binaries resolve their IAT at runtime; static sees a stub,
  the debugger sees the resolved table. This is literally what the *Scylla* tool reconstructs.
- **Unpacked code.** A self-decrypting/UPX-packed sample only exists as real code *after* it
  unpacks itself in memory — a runtime dump is the only place the analyzable code lives.
- **Resolved indirect / virtual calls.** `call [rax]` and vtable dispatch are a static guess and a
  runtime fact. Dynamic resolves the edge the program *took*.
- **Anti-analysis defeated by just running it.** The sample does the deobfuscation for you.

These are not refinements of static output — they are *facts static cannot produce*. That is the
case for a second producer, not a better engine.

## Why it fits the architecture (the whole point of the narrow waist)

A dynamic producer is **another implementation of the engine port** (DD-009/040), or a sibling
binary-source adapter (DD-018): it emits the same model — functions, edges, the durable artifact —
just sourced from a live process instead of a static decode. The narrow waist (one model, two
producers) is precisely what makes this an *adapter*, not a rewrite. The consume side (ports,
heads, re-anchoring, collaboration) does not change at all.

It also slots into machinery we already built:

- **Provenance (DD-007)** already exists as a seam. "This import was *observed* at runtime" vs
  "this target was *inferred* statically" is a provenance distinction, not a new core concept.
- **Merge (DD-027 `collaborate`)** already merges two producers' views of the same binary,
  surfacing disagreements instead of silently overwriting. Static-vs-dynamic *is* that, with a
  twist (below).

## The hard parts — why "later," not "now"

1. **Executing hostile code is a different security tier than DD-034.** DD-034 sandboxes a *parser*
   reading adversarial bytes; a read-only, capless, no-egress container is enough. A dynamic
   producer **runs the malware**. Containment for execution is a categorically harder problem —
   microVM/full-VM isolation, kernel-boundary trust, network *deception* (not just `--network
   none` — many samples won't unpack without a believable C2 to phone), snapshot/restore,
   timing/anti-VM evasion. Our current sandbox is necessary but nowhere near sufficient for it.
   This is the single biggest reason to defer.

2. **The static + dynamic merge is not symmetric.** Dynamic facts are *higher* confidence where
   observed (a resolved import is ground truth) but **partial** — they cover only executed paths,
   so most of the program is dark. The merge can't treat them as peers: dynamic should win the
   overlap (real beats inferred) yet static must own everything dynamic never reached. That is a
   real extension of `collaborate`'s conflict model (confidence-weighted, coverage-aware), not a
   free reuse.

3. **The tooling is Windows-centric and GUI-shaped.** x64dbg is a Windows debugger; *Scylla* and
   *ScyllaHide* are its plugins. Driving them headless as a *producer* — scripted, reproducible,
   no human at the GUI — is its own integration project (x64dbg has automation surfaces, but they
   are not built for batch model-emission). A Linux/cross-platform dynamic producer is arguably a
   different tool (a ptrace/Frida/QEMU-based harness) wearing the same port.

4. **The static path isn't even fully exploited yet.** Decompilation-on-demand is a stub; the warm
   engine is unbuilt; cross-arch re-anchoring wants Version Tracking. Spending the next big effort
   on *executing* samples before the *reading* of them is finished is out of order.

## Recommendation

- **Defer**, and keep it explicitly on the roadmap as a *post-v1 producer adapter* — the hexagon
  guarantees it lands as an adapter, so deferring costs nothing structurally.
- **Do not** weaken the DD-034 model to "get ready" for it — execution containment is a separate
  design, not an extension of the parser sandbox. When the time comes it gets its own threat model.
- **The cheap, no-regret groundwork** to do *whenever* a producer (static or dynamic) needs it:
  make producer **provenance** first-class on facts/edges (DD-007), and make `collaborate`
  confidence- and coverage-aware (DD-027). Both are useful for static-only collaboration too, so
  they earn their keep before any dynamic producer exists.
- **First real step, when prioritized:** a *narrow* prototype — ingest a single runtime artifact
  (a resolved IAT from a Scylla dump, or a memory dump of an unpacked region) into the model
  through the engine port, and merge it against the static model of the same sample. Prove the
  *seam* (as DD-004 re-anchoring and DD-040 gRPC were proven) before betting on the harness.

The name collision is, as the backlog notes, on-brand: the RE scene loves "Scylla." That is not a
reason to build it. It is a reason to make sure ours is the one worth the name.

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
