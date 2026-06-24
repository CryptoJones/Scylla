# Harness M1 — the containment tier (first cut): DONE; GAP-5/7 red-team GATE pending

**Status: the tier stands up, isolates, and tears down — proven on a benign payload.** This is
milestone M1 of [../HARNESS-BUILD-PLAN.md](../HARNESS-BUILD-PLAN.md). It is NOT the finished tier:
the M1 *gate* — a red-team pass proving a HOSTILE guest can't escape, reach the network, or exhaust
the host (GAP-5/GAP-7 of [../HARNESS-THREAT-MODEL.md](../HARNESS-THREAT-MODEL.md)) — is the next
checkpoint, and nothing proceeds to M2 until it passes. **No hostile code has run; no Scylla
integration yet.**

## Host feasibility (ronin28, assessed read-only first)

| Check | Result |
|---|---|
| Hardware virt | `vmx` (Intel VT-x) present |
| `/dev/kvm` | present, `root:kvm` 0660 — and the user is in the `kvm` group → **runs without sudo** |
| kvm modules | `kvm_intel` + `kvm` loaded |
| Hypervisor | QEMU 10.2.1 installed (`microvm` machine supported); Firecracker not installed |
| Guest init | static `busybox` present; `cpio`+`gzip` present |
| RAM | ~9 GB free — a microVM needs ~128–256 MB |
| Bare metal | `systemd-detect-virt` → none (not nested) |

The one elevation needed is reading the host kernel (`/boot/vmlinuz-*` is `0600 root`) to feed
`qemu -kernel`; the runner copies it with `sudo` (or takes a readable `$KERNEL`).

## What M1 builds (`m1-microvm.sh`)

An ephemeral KVM microVM with the containment knobs the threat model requires, on a benign payload:

- **`-machine microvm` + `-accel kvm`** — a lean VM-grade sandbox (not a process/namespace sandbox,
  which is the DD-034 *parser* tier and insufficient for executing code).
- **No network**: `-nic none` — the guest has zero interfaces (verified from inside).
- **No host filesystem**: no `-drive`/`-virtfs` — only the in-memory initramfs.
- **Resource-capped**: `-m 256 -smp 1`, plus a **40 s `timeout` kill-switch** (GAP-7 stopgap).
- **Ephemeral**: the guest's `poweroff` + `-no-reboot` ends qemu; the work dir is `mktemp` + trap-cleaned.
- The guest `/init` (static busybox) prints a marker, lists its network interfaces, and halts.

## Measured result

```
M1_GUEST_RAN ok uname=Linux 7.0.0-22-generic      <- the benign payload executed INSIDE the microVM
M1_GUEST_NET_IFACES=[]                             <- zero network interfaces — no egress
[m1] PASS — ... ephemeral, no-network, 256M-capped microVM, then it was destroyed (qemu rc=0).
```

So: **execution** (a program ran in the guest), **containment** (no network, no host FS), and
**ephemeral teardown** (clean poweroff, qemu exited) — the three things M1 had to show.

## What this does NOT yet prove (the gate)

M1's *gate* is adversarial, and is deliberately not yet attempted:

- **GAP-5 (escape):** a guest *trying* to break out of the VM/hypervisor to the host. A benign halt
  proves the happy path, not the absence of an escape. Closing this is a red-team exercise (and a
  reason M5 should move to Firecracker — a far smaller host attack surface than full QEMU).
- **GAP-7 (resource exhaustion):** a fork-bomb / balloon racing the kill-switch; `-m` + `timeout` are
  a stopgap, not a cgroup-grade bound.

Until that red-team passes, the tier is "boots + isolates a cooperative guest," not "contains a
hostile one" — so M2 (the observation channel) and especially M5 (hostile samples) stay gated.

## Next

1. The **GAP-5/7 red-team** against this tier (the M1 gate).
2. Then **M2** — the one-way, bounded, untrusted observation channel out of the guest.

Reproduce: `./m1-microvm.sh` (set `$KERNEL` to a readable bzImage to skip the kernel-copy sudo).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
