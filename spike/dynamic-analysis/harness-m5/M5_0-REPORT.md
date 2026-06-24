# Harness M5.0 — migrate the tier to FIRECRACKER + re-red-team: **PASS** (synthetic, benign)

M5 runs real malware, for which the build plan recommends migrating the containment tier from QEMU
`microvm` to **Firecracker** — a minimal VMM (virtio-mmio + serial only; no PCI/BIOS/legacy-device
emulation; Rust; optional `jailer`) with a far smaller host attack surface than full QEMU. M5.0 stands
the M1 containment knobs up on Firecracker and re-runs the GAP-5/7 red team on **synthetic** attacks.
**Both pass** — so the recommended tier is de-risked. This is **not** real malware (that is M5.3, on an
isolated node + a corpus + an external pen-test, per [HARNESS-M5-PLAN.md](../HARNESS-M5-PLAN.md)).

## Setup (ronin28)

- **Firecracker v1.16.0**, installed user-level (`~/.local/bin`, the official static release binary —
  no system package, no root).
- **Kernel:** Firecracker needs an *uncompressed* `vmlinux`, not a bzImage; one was extracted from the
  host kernel via `scripts/extract-vmlinux`. (A production M5 would use a *minimal hardened* guest
  kernel, not the host's general kernel — noted as M5 hardening.)
- **Guest:** the same static-busybox initramfs as M1, booted via Firecracker's `initrd_path`.
- **Containment knobs → Firecracker config:** no `network-interfaces` (= `-nic none`), no `drives`
  (= no host FS), `vcpu_count: 1` + `mem_size_mib: 256` (= `-smp 1 -m 256`), a `timeout` kill-switch.
  Clean teardown via a triple-fault `reboot` (Firecracker's exit signal) — **guest-reset → rc ≠ 124;
  only the kill-switch yields rc == 124** (this differs from QEMU, where guest `poweroff` → rc 0).

## Benign tier (`m5_0-firecracker.sh`)

```
FC_GUEST_RAN ok uname=Linux 7.0.0-22-generic   <- the host kernel boots + runs /init under Firecracker
FC_GUEST_NET_IFACES=[]                          <- no network
[m5.0] PASS — benign guest ran in an ephemeral, no-network, 256M-capped FIRECRACKER microVM, then it exited (rc=1).
```

## GAP-5/7 red team (`m5_0-redteam.sh`) — all assertions PASS

| Attack | Firecracker result |
|---|---|
| **GAP-5 net** (NIC up, DHCP, connect incl. `169.254.169.254` metadata) | `lo` only; **egress blocked** |
| **GAP-5 host FS** (scan + mount `vda`/`9p`) | zero block devices; **mounts blocked**; canary untouched |
| **GAP-5 devices** | **no PCI bus at all** (Firecracker has none), no virtio, **no vsock** |
| **GAP-7 CPU spin** | **reaped** by kill-switch (rc=124); host heartbeat gap **0.31s** |
| **GAP-7 memory balloon** | OOM'd inside the VM; host RAM drop **100 MB** (bounded by the 256M cap) |
| **GAP-7 fork bomb** | **reaped** (rc=124); host proc table **473→477** (flat) |
| **GAP-9 persistence** | both boots **CLEAN** — no cross-run leak |

```
[RT] FIRECRACKER GATE PASS — the migrated tier contained every synthetic hostile guest
     (no escape, no host exhaustion, reaped within budget, ephemeral), same as the QEMU tier —
     on a SMALLER VMM attack surface.
```

The Firecracker tier held **at least as well** as the QEMU `microvm` tier (16/16 there), and exposes
*less* — notably **no PCI bus**, removing a whole class of device-emulation escape surface (the GAP-5
residual that motivated the migration).

## What this does and does NOT establish

- **De-risked:** Firecracker is the viable M5 tier on this host; the M1 containment knobs port to it;
  it survives the synthetic GAP-5/7 red team with a smaller attack surface. Reproducible:
  `VMLINUX=<uncompressed> ./m5_0-redteam.sh` (exit 0).
- **Still NOT real malware:** the guests are synthetic attackers, contained *by the boundary under
  test*, on ronin28. **M5.3 (real malware)** still requires an **isolated node**, a **hardened minimal
  guest kernel** (not the host's), the **`jailer`** (Firecracker's drop-priv/cgroup/namespace wrapper)
  in front of `firecracker`, a **malware corpus**, and an **external pen-test** — see HARNESS-M5-PLAN.md.
  The residual QEMU-device-0-day risk is *reduced* by the smaller Firecracker surface but only an
  external pen-test against real samples closes GAP-5 for hostile code.

## Next on the no-malware track

**M5.1** — generalize the M3 observer from `LD_DEBUG` (cooperative samples) to **ptrace / QEMU-user
trace** (uncooperative/packed samples), validated on benign. Then **M5.2** (benign uplift). Only then,
behind the provisioning checklist, **M5.3/M5.4**.

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
