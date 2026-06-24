# Harness M5.3 prep — anti-analysis: a ptrace-based observer is detectable (GAP-8 finding)

"Anti-analysis" is one of M5.3's named behavior classes. Unlike the others this is a **finding, not a
clean PASS** — and that honesty is the point. A benign probe reads `/proc/self/status` `TracerPid` to
detect a ptrace observer, run in the tier **both ways**.

## Measured

```
M5_3_AA_CONTROL=0          <- no observer: TracerPid == 0
M5_3_AA_TRACED=1           <- under the syscall observer (strace): TracerPid != 0  ← DETECTED
M5_3_AA_OBSERVED_PROBE=[1] <- the harness still captured the probe (read of /proc/self/status)
```

So an **in-guest ptrace-based observer (M5.1 `ltrace` / M5.3 `strace`) is detectable** — a sample that
checks `TracerPid` knows it is being watched. **GAP-8 (evasion) is real and confirmed:** a sample that
detects the harness can lie, stay benign, or bail. The harness *does* still observe the anti-analysis
behavior itself (the `/proc/self/status` read), so the analyst at least learns the sample is
evasion-aware.

## Mitigations (for M5.3 design)

1. **Stealthier, out-of-guest observation.** A ptrace observer lives *inside* the guest and sets
   `TracerPid`. Observing from **outside** the guest — QEMU-TCG instruction tracing, or hypervisor
   introspection (read guest memory/registers from the VMM) — leaves no in-guest `TracerPid` and is far
   harder to detect. Firecracker's minimal device model + KVM make VMM-side observation the right M5.3
   direction for evasion-aware samples; the in-guest `strace`/`ltrace` observers are the cheap path for
   non-evasive ones.
2. **Provenance down-ranking (already built).** This is *why* dynamic observations are never trusted as
   ground truth: a sample that detects analysis may feed false behavior. Observations stay
   `producer="dynamic"`, `confidence < 100` (DD-007), down-ranked by `collaborate` (DD-027), and the
   analyst is told coverage was partial. GAP-8 is inherent to dynamic analysis — the discipline is to
   record it, not pretend it away.

## For M5.3

This closes the loop on M5.3's named behavior classes, de-risked on benign samples:
**anti-analysis (this), network beaconing, persistence** (each `harness-m5/m5_3-*.sh`), plus
**fork-bomb / resource exhaustion** (the M1/M5.0 red team). Each shows the observe+contain pair — or,
here, the honest limit and its mitigation — before any real malware runs. Real malware still needs the
M5.3 infrastructure (HARNESS-M5-PLAN.md), where the out-of-guest observer is the evasion-hardening step.

Reproduce: `VMLINUX=<uncompressed> ./m5_3-antianalysis.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
