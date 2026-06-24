# Harness M1 — the GAP-5 / GAP-7 RED TEAM: **GATE PASS** (configured containment, synthetic attacks)

[`m1-microvm.sh`](m1-microvm.sh) proved the tier contains a *cooperative* guest. This is its **gate**:
[`m1-redteam.sh`](m1-redteam.sh) boots guests that *deliberately attack* the containment knobs and
asserts, **from the host**, that nothing reached past the VM boundary. **All 16 assertions across 5
scenarios PASS** — so the M1 gate ([../HARNESS-BUILD-PLAN.md](../HARNESS-BUILD-PLAN.md)) is cleared and
M2 is unblocked.

This is adversarial testing of **our own sandbox** with **synthetic** attacks — **not** real malware
(that is M5, which additionally requires an isolated node + an external pen-test). The attacks are
contained *by the very boundary under test*: `-nic none`, no `-drive`, `-m 256 -smp 1`, a wall-clock
kill-switch. The host (24 cores, ~9.5 GB free) cannot be starved by a guest pinned to 1 vCPU / 256 MB —
which is the property being proven.

## What it attacks, and what the host measured

Run on ronin28, QEMU 10.2.1 `microvm` + KVM, host `timeout`-kill code = 124.

### Scenario A — GAP-5 escape (network, host FS, devices, hypervisor)
The hostile guest brings up `eth0`, runs `udhcpc`, and tries TCP to the usual QEMU host-gateway
(`10.0.2.2:53`) and a public IP (`8.8.8.8:53`); scans `/dev` + `/proc/partitions` for block devices and
attempts `mount` of `/dev/vda`, `9p` (`trans=virtio`), and `virtiofs`; enumerates PCI/virtio and probes
`/dev/vsock` + `/dev/vhost-vsock`. A host **canary file** is checked afterward.

| Probe | Observed | Verdict |
|---|---|---|
| Network interfaces | `[lo]` (loopback only) | no NIC |
| Connect host-gw / public | **both blocked** | no egress |
| Block devices / partitions | `[]` / `[]` | no host disks |
| Mount vda / 9p / virtiofs | **all blocked** | no host FS |
| PCI / virtio devices | `[]` / `[]` | minimal surface |
| `/dev/vsock`, `/dev/vhost-vsock` | **absent** | no host channel |
| Host canary | **unchanged** | guest reached no host FS |

### Scenario B — GAP-7 CPU kill-switch
Guest spins forever (`while :; do :; done`) and never halts — only the wall-clock can stop it.
**`rc=124`** (reaped by the kill-switch); host heartbeat **max gap 0.31 s** → the host stayed responsive
while the guest pinned its single vCPU (1 of the host's 24).

### Scenario C — GAP-7 memory cap
Guest mounts `tmpfs size=1024m` (4× the VM's RAM) and `dd`s zeros into it until it can't.
The guest **OOM-killed inside the VM** (2 OOM-killer events in the serial; the `dd`s were reaped, the
guest survived and powered off cleanly, `rc=0`). Host `MemAvailable`: **9561 MB → min 9389 MB during =
171 MB drop** — that is qemu's own ~256 MB footprint, **not** the guest's runaway demand. The `-m 256`
cap bounded the blast radius to the VM; the host's RAM was never at risk.

### Scenario D — GAP-7 fork bomb
Guest spawns `sleep` processes in a loop (logged **≥1750** before being reaped). **`rc=124`** (reaped);
host process table **466 → 465** (i.e. *flat* — the guest's thousands of processes live in the VM's PID
namespace and never appear on the host); host heartbeat **max gap 0.31 s**.

### Scenario E — GAP-9 ephemerality
The **same** initramfs is booted twice; run 1 writes `/PWNED_BY_PRIOR_RUN`, run 2 checks for it. Both
runs report **CLEAN** — a fresh RAM rootfs each boot, no cross-run persistence.

## Verdict

```
[RT] GATE PASS — the M1 microVM contained every synthetic hostile guest:
     no escape (net/FS/device/vsock), no host exhaustion, reaped within budget, ephemeral.
```

## What this does and does NOT close

- **GAP-7 (resource exhaustion):** **closed** for the configured tier — spin, balloon, and fork-bomb are
  each bounded to the VM and reaped within budget; the host is unaffected.
- **GAP-9 (cross-run persistence):** **verified** — ephemeral per-run rootfs, no leak.
- **GAP-5 (escape):** **closed for the *configured surface*** — the guest has no network, no host FS, no
  host devices, and no vsock to reach the host *by configuration*, and a guest actively trying to use
  those vectors found nothing. The **residual** is a guest exploiting a **QEMU device-emulation 0-day**
  to execute in the qemu host process — out of scope for a synthetic red team, mitigated already by
  running qemu **unprivileged** + the **`microvm` machine's minimal device set**, and is precisely what
  **M5** addresses: migrate the tier to **Firecracker** (a far smaller host attack surface) and subject
  it to an **external pen-test** against *real* malware behaviors. Until then this tier contains a
  *synthetic* hostile guest, which is the M1 gate — not yet a *real-malware* tier (M5).

## Next (now unblocked)

**M2 — the one-way observation channel:** a single bounded channel out of the guest (a read-back volume
/ vsock) carrying a recorded trace, which the host treats like a stranger's `.scylla` (DD-036 caps,
validate-then-quarantine, never `eval`); its gate is the **GAP-6** fuzz (adversarial/oversized/malformed
traces never panic or OOM the host parser).

Reproduce: `KERNEL=<readable-bzImage> ./m1-redteam.sh` (exit 0 = gate pass).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
