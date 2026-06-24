# Harness M5.1 — the uncooperative in-guest observer: **PASS** (benign)

M3's observer recovered the resolved IAT via the glibc loader's `LD_DEBUG=bindings` — which needs a
**cooperative** sample and loader. A statically-linked, custom-packed, or `LD_DEBUG`-suppressing binary
defeats it. **M5.1 recovers the same IAT by external ptrace observation** (`ltrace` intercepts PLT
calls), with **`LD_DEBUG` unset** — so it works on an *uncooperative* sample — and it runs **inside the
Firecracker tier** (M5.0), with the recovered IAT crossing the M2 channel to the host validator.

## What it does

`m5_1-observe.sh` stages `ltrace` + its 6 shared-lib deps (`libelf`, `libselinux`, `libz`, `libzstd`,
`libpcre2-8`, `libc`) + `ld.so` + the benign sample + the M2 framer into an initramfs (`LD_LIBRARY_PATH`
data-driven, no `ld.so.cache`), boots it under **Firecracker** (no net, no drives, 1 vcpu / 512 MiB,
`timeout` kill-switch), and inside the guest runs:

```
unset LD_DEBUG                       # <- explicitly uncooperative: NOT the loader's logging
ltrace -f -e '*' -o /tmp/lt.out -- /sample
```

It filters `ltrace`'s output to the sample's own PLT calls (`sample->FUNC`), turns them into the JSON
trace, frames it (`m3-frame`, base64+FNV matching `channel.rs`), and writes the M2 frame on serial. The
host reads it back through the bounded validator (`m2-read`) and checks ground truth.

## Measured (inside the Firecracker tier)

```
GUEST(M5.1): ltrace-observing the benign sample (LD_DEBUG unset; external PLT interception)
GUEST(M5.1): recovered 3 imports via ptrace; emitting framed trace
[m2] ACCEPTED 3 observed edge(s) — bounded + validated, never eval'd:
[m2]   sample -> getpid / puts / snprintf  (conf 92)
[m5.1] PASS — recovered the benign sample's resolved IAT (getpid puts snprintf), LD_DEBUG unset, over the validated M2 channel.
```

The uncooperative observer recovered **exactly** the sample's known IAT (`getpid`/`puts`/`snprintf` —
the same ground truth M3 hit), with **no loader cooperation**, inside the contained tier, and it arrived
validated over the channel. So the producer chain now runs on the **M5.0 Firecracker tier** with an
observer that doesn't depend on the loader: **execute → (ptrace-)observe → channel → validate**.

## Scope — what this establishes, and the honest limits

- **Establishes:** the observer generalizes past `LD_DEBUG` — `ltrace`/ptrace recovers the IAT of an
  *uncooperative* sample (verified by recovering it with `LD_DEBUG` unset), and it runs *inside* the
  Firecracker tier. The hardest non-infrastructure piece of M5 is de-risked on a benign sample.
- **ltrace was installed** on ronin28 (`apt`, a system change) — fine for a benign de-risk; a production
  M5 guest would bake a minimal tracer into the hardened guest image, not apt-install on the host.
- **Honest limits (still benign, GAP-8 inherent):** dynamic observation sees imports that are *called*
  — a packed sample's hidden imports surface only once unpacked code runs them (the nature of dynamic
  coverage), and a *hostile* sample can detect ptrace and anti-trace. M2 guarantees it can't break the
  host; the dynamic stamp (DD-007, `confidence < 100`) guarantees the matcher never trusts it as ground
  truth (DD-027 down-ranks). Real malware + anti-analysis hardening is **M5.3** (isolated node + the
  `jailer` + a malware corpus + an external pen-test, per HARNESS-M5-PLAN.md).

## Next — M5.2

Close M4's loop on a benign sample: ingest the sample to its own `.scylla`, run this observer on the
*same* sample, merge by `StableId`, and measure the uplift with `WRONG = 0` preserved.

Reproduce: `VMLINUX=<uncompressed> ./m5_1-observe.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
