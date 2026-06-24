# Harness M4 — the dynamic producer, end-to-end on a benign sample: **first cut DONE**

M1 contains a hostile guest; M2 carries a trace out, bounded + validated; M3's observer produces a
real resolved IAT inside the tier. **M4 wires all three behind the `DynamicHarness` trait** the spike
stubbed (`src/harness.rs`) — so a dynamic producer feeds the one model through the same narrow waist
the static producer does, stamped DD-007 `producer="dynamic"`. The gate: on a benign sample the
producer's observations are first-class **and down-rankable**, with `WRONG = 0` intact.

## `MicroVmHarness: DynamicHarness` — the trait realized against the real tier

`RecordedHarness` replayed a canned trace and executed nothing. **`MicroVmHarness::observe` runs the
real contained pipeline:** it invokes the M3 observer (`harness-m3/m3-observe.sh --raw`) — which boots
the M1 microVM, runs the benign sample under the loader, and recovers its resolved IAT — and reads the
trace back over the **M2 channel through the bounded validator** (`channel::read_trace`). So the full
chain runs for real:

```
execute (M1 microVM) → observe (M3 resolved IAT) → channel (M2 serial) → validate (channel.rs) → ObservedEdge[]
```

Measured (`m4-producer.sh` / `cargo run -- m4`, on the real microVM):

```
[m4] containment: microVM (M1): KVM, ephemeral, no egress (-nic none), no host FS, 256M cap + kill-switch ...
[m4] observed 11 runtime edge(s) from a REAL contained run, via the validated M2 channel:
[m4]   sample -> getpid     ==> DD-007 Provenance { producer: "dynamic", confidence: 95 }
[m4]   sample -> puts       ==> DD-007 Provenance { producer: "dynamic", confidence: 95 }
[m4]   sample -> snprintf   ==> DD-007 Provenance { producer: "dynamic", confidence: 95 }   (+ libc startup/alloc)
[m4] VERDICT: GO — ... a dynamic producer feeds the one model as a down-rankable second source (DD-027), with WRONG=0 intact.
```

## WRONG = 0, by stamping discipline (not by touching the matcher)

M4 **consumes** the merge machinery; it does not modify `scylla-merge` (the re-anchoring matcher and
its `WRONG = 0` gate are untouched, as in DD-027). The invariant that keeps dynamic data safe is the
**stamp**: a dynamic observation is partial-coverage by nature (GAP-8 evasion is inherent), so it is
**never** stamped certain (`user`/100) — here `confidence = 95`. Therefore DD-027 `collaborate` can
only ever let it win a disagreement against a *lower*-confidence fact, and can **never** silently
overwrite a confident static/user fact; a near-tie is flagged, never guessed. The hermetic test
`harness::m4::dynamic_observations_are_never_stamped_certain` (`cargo test`) asserts the discipline;
`collaborate`'s own DD-027 tests prove the merge behaviour it relies on.

## Scope — first cut, and the honest completion

- **Done:** the producer interface runs end-to-end against the *real* tier on a *benign* sample, and
  its observations arrive validated + provenance-stamped — a dynamic producer behind the same port as
  the static one, opt-in, never the default.
- **The honest completion (M4→M5):** merging the observations into the *same sample's* static model
  (to measure uplift the way the seam spike did on `mathlib`) needs that sample's `.scylla` — i.e. an
  **ingest** of the sample — which the seam already proved lands by `StableId`. And a *hostile* sample
  needs the M3 observer generalized to **ptrace / QEMU-user trace** (no loader cooperation) plus the
  M1 red-team re-run + an external pen-test. Both ride with **M5**.
- **GAP-8 (evasion)** stays open and inherent: a sample can emit a valid-but-partial/lying trace. M2
  guarantees it can't break the host; the dynamic stamp guarantees the matcher never trusts it as
  ground truth. That is the bound dynamic analysis can offer, recorded honestly in the provenance.

Reproduce: `KERNEL=<readable-bzImage> ./m4-producer.sh` (exit 0); `cargo test` (hermetic).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
