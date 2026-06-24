# Harness M5.3 prep — the syscall-level observer (packing-resistant), in the tier: **PASS** (benign)

The packing finding ([M5_1-PACKED-FINDING.md](M5_1-PACKED-FINDING.md)) showed M5.1's PLT-interception
observer is defeated by a packer, while a syscall trace survives — so M5.3 (real malware, routinely
packed) needs a syscall-level observer. This **de-risks that observer on benign samples, inside the
Firecracker tier** (M5.0): it `strace`s both a normal and a UPX-packed benign binary in the guest and
confirms it recovers their behavior from **both**.

## What it does (`m5_3-syscall.sh`)

Stages `strace` + its 6 lib deps + `ld.so` + a benign sample + its UPX-packed copy into an initramfs,
boots it under Firecracker (no net, no drives, 1 vcpu / 512 MiB, `timeout` kill-switch), and inside the
guest runs `strace -f -e trace=getpid,write -- /<bin>` on each, reporting the recovered behavior.

## Measured (inside the Firecracker tier)

```
M5_3_TRACE bin=sample        getpid=1 write1=1
M5_3_TRACE bin=sample_packed getpid=1 write1=1
[m5.3] PASS — recovered behavior from BOTH the normal AND the PACKED binary inside the tier.
```

The syscall observer recovered the program's behavior (`getpid()` + `write(1,…)`) from **both** the
normal binary **and the packed one** — the packed case being exactly where the PLT-interception
observer (M5.1) recovered nothing. So the packing-resistant observer **works inside the contained
tier**, not just on the host.

## The observer story, now complete (on benign samples, in the tier)

| Observer | Recovers | Cooperative loader? | Packing-resistant? | Where proven |
|---|---|---|---|---|
| M3 `LD_DEBUG` | resolved IAT | **requires it** | no | M3 (microVM) |
| M5.1 `ltrace` (PLT interception) | resolved IAT | no | **no** (defeated by packing) | M5.1 (Firecracker) |
| **M5.3 `strace` (syscall)** | **behavioral trace** | no | **yes** | **here (Firecracker)** |

So the harness has a *named-IAT* observer (for cooperative, unpacked samples) **and** a
*behavioral/syscall* observer (packing- and obfuscation-resistant) — both proven inside the Firecracker
tier. The dynamic producer picks the observation that fits the sample; both feed the model as
partial-coverage `producer="dynamic"` data (DD-007), down-rankable (DD-027), never ground truth.

## Still NOT real malware

Benign samples, contained by the boundary under test, on ronin28. **M5.3 proper** (real malware) still
needs the **isolated node** + the Firecracker **`jailer`** + a **hardened guest kernel** + a **malware
corpus** + an **external pen-test** (HARNESS-M5-PLAN.md), and the syscall observer must then be hardened
against anti-trace evasion (GAP-8, inherent — recorded in provenance, never hidden). This de-risk
removes the *observer* unknown for packed samples; the *infrastructure* wall remains the operator's.

Reproduce: `VMLINUX=<uncompressed> ./m5_3-syscall.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
