# Harness M5 — widen to HOSTILE samples: the staged plan + the infrastructure wall

The benign harness is built and gated-green: **M1** containment tier (+ GAP-5/7 red team), **M2**
bounded observation channel (+ GAP-6 fuzz), **M3** in-guest observer (resolved IAT on a benign
sample), **M4** the dynamic producer end-to-end on a benign sample (`MicroVmHarness`, DD-007 stamped,
`WRONG = 0` intact). **M5 is the actual point — running real malware — and it is a different kind of
step:** most of it is *infrastructure and external review*, not code, and it must not start until that
infrastructure exists. This plan exists so M5 is provisioned against a concrete checklist, the same
plan-before-build discipline that preceded M1.

## Why M5 is a wall, not a loop iteration

Everything to here ran a *cooperative, benign* program inside the tier on **ronin28** (CJ's working
laptop). Real malware inverts the remaining assumptions: it will *try* to escape, beacon, persist, and
detect the harness. Three things make M5 categorically different and **not autonomously completable on
this box**:

1. **It needs an isolated node — not ronin28.** A dedicated/air-gapped host (or a cloud VM that is
   itself disposable and network-policy-isolated), because a real escape (GAP-5 residual: a QEMU/Fire-
   cracker device 0-day) must not reach the analyst's working machine, fleet, or LAN.
2. **It needs real malware + a handling policy** — a sourced, hashed, access-controlled corpus, and a
   rule for storage/transport that never lands a live sample on a general-purpose host.
3. **It needs an external pen-test.** Self-certifying containment for *hostile* code is the failure
   mode the threat model was written to prevent; GAP-5..9 must be re-validated by someone who isn't us.

Under CJ's standing pre-authorization this is still a **technical-readiness gate, not a permission
gate**: the authorization is given; the *infrastructure* is what's missing. No real malware runs until
1–3 exist and the staged gates below pass.

## What CJ must provision (the checklist)

- [ ] **An isolated node** — dedicated host or disposable cloud VM; no route to the working LAN/fleet;
      KVM-capable; treated as burnable.
- [ ] **Firecracker + jailer** installed on that node (M5.0 migrates the tier to it).
- [ ] **A malware corpus** — sourced, hashed, access-controlled; a written handling/retention policy.
- [ ] **An external pen-tester** + a scope statement (escape / channel-injection / exhaustion /
      persistence / evasion-honesty).

## The staged M5 sub-plan (each gated; no real malware before M5.3)

### M5.0 — migrate the tier to Firecracker, re-red-team it (still benign)
- **Build:** port M1's containment knobs to a **Firecracker/jailer microVM** (a far smaller host attack
  surface than full QEMU — the right tier for hostile code), on the isolated node. Re-run the M1 GAP-5/7
  red team (`m1-redteam.sh` analogue) against it, still on **synthetic** attacks.
- **Gate:** the Firecracker tier passes the same 16 assertions M1's QEMU tier did. **Autonomously
  de-riskable now** *without* malware: a Firecracker feasibility spike + a benign red-team re-run.
- **DONE (2026-06-24):** `harness-m5/m5_0-firecracker.sh` (benign tier) + `harness-m5/m5_0-redteam.sh`
  (the gate). Firecracker v1.16.0 (user-level), uncompressed `vmlinux` extracted from the host kernel,
  the M1 busybox initramfs via `initrd_path`, M1's knobs as Firecracker config (no `network-interfaces`,
  no `drives`, 1 vcpu / 256 MiB, `timeout` kill-switch). **GATE PASS** — benign tier ran/no-net/
  ephemeral, and the GAP-5/7 red team passed every assertion *on a smaller attack surface than QEMU*
  (notably **no PCI bus at all**). See `harness-m5/M5_0-REPORT.md`. Production hardening deferred to
  M5.3: a *minimal hardened* guest kernel (not the host's) + the **`jailer`** in front of `firecracker`.

### M5.1 — generalize the observer for uncooperative samples (still benign)
- **Build:** M3's observer recovers the IAT via `LD_DEBUG`, which needs a *cooperative* sample. Replace
  it with **ptrace / QEMU-user instruction tracing** that observes resolution + indirect-call edges
  *without* the sample's cooperation (a statically-linked / custom-packed binary).
- **Gate:** on a *benign* packed/stripped sample with a known IAT, the ptrace observer recovers it
  (ground truth), reproducibly. **Autonomously de-riskable now** *without* malware.
- **DONE (2026-06-24):** `harness-m5/m5_1-observe.sh`. The observer generalizes from M3's `LD_DEBUG`
  (cooperative) to **external ptrace** (`ltrace` intercepts PLT calls) with `LD_DEBUG` **unset** — so it
  works on an uncooperative sample — and runs **inside the Firecracker tier** (M5.0), the recovered IAT
  crossing the M2 channel to the host validator. **PASS:** recovered the benign sample's exact IAT
  (`getpid`/`puts`/`snprintf`) over the validated channel. `ltrace` + its 6 lib deps staged into the
  initramfs. Honest limits (GAP-8 inherent): dynamic coverage sees only *called* imports; a hostile
  sample can anti-trace — a production guest bakes a minimal hardened tracer, not apt-`ltrace`; that
  hardening is M5.3. See `harness-m5/M5_1-REPORT.md`.

### M5.2 — close M4's loop on a benign sample (uplift, WRONG = 0)
- **Build:** ingest a benign sample to its own `.scylla` (the seam proved a runtime IAT lands by
  `StableId`), run the real observer on the *same* sample, merge, and **measure the uplift** the seam
  spike predicted — now from a real contained run — with `WRONG = 0` end to end. (Needs the engine.)
- **Gate:** measurable uplift on benign samples, `WRONG = 0` preserved.
- **DONE (2026-06-24):** `harness-m5/m5_2-uplift.sh` + the spike's `m5_2` path. Closes the loop WITHOUT
  the engine, using a real in-repo artifact: the `mathlib` fixture + its `mathlib.scylla`. A gdb
  function-entry tracer observes the real runtime call graph (`main→{gcd,fib,factorial,sum_to}`,
  `fib→fib`); the merge resolves each edge to a `StableId` by identity, confirms it against the static
  `callees`, and stamps DD-007 `producer="dynamic"`. **PASS — 5/5 confirmed, 0 unmatched = `WRONG=0`**.
  Internal call edges are the provenance-carrying observation (`EdgeProvenance`, `model.capnp @13`); the
  merge only ever CONFIRMs or ADDs, never overwrites (`callees`+matcher untouched). On a packed sample
  the same merge would ADD the dynamically-resolved edges static missed. See `harness-m5/M5_2-REPORT.md`.
  **With this the entire no-malware track is complete; only M5.3/M5.4 (real malware + infra) remain.**

### M5.3 — introduce real malware, one class at a time (isolated node, opt-in)
- **Build:** only now, on the isolated node, opt-in, introduce real samples **one behavior class at a
  time** — anti-analysis → network-beacon attempts → fork bombs → persistence — re-validating GAP-5..9
  after each.
- **Gate:** every class contained; observations stay `producer="dynamic"` + partial-coverage confidence
  (GAP-8: a sample that lies/evades can only feed down-rankable data, never ground truth, and the
  analyst is told coverage was partial).

### M5.4 — external pen-test
- **Gate:** GAP-5..9 re-validated against hostile samples **by an external pen-tester**; findings
  remediated before the dynamic producer is offered as anything but an isolated-node, opt-in tool.

## Non-negotiables (unchanged)

Isolated node only; opt-in, never default; one milestone/one malware-class at a time, behind its gate;
**no real malware before M5.3** (and not before M5.0's Firecracker red-team passes); do **not** weaken
DD-034; `WRONG = 0` is sacred and the matcher stays untouched (the producer only ever feeds
down-rankable, provenance-stamped observations). Evasion (GAP-8) is inherent — recorded in provenance,
never hidden.

## Progress available WITHOUT the malware infrastructure

So the loop need not idle waiting on provisioning: **M5.0** (Firecracker feasibility + benign
red-team), **M5.1** (ptrace/QEMU-user observer on benign samples), and **M5.2** (benign uplift) are all
de-riskable on this box with **no hostile code**. Only **M5.3/M5.4** require the isolated node + corpus
+ external pen-test.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
