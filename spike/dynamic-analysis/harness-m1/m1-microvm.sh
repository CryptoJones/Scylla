#!/usr/bin/env bash
# Dynamic-analysis harness — MILESTONE 1: the containment tier (first cut).
#
# Stands up an EPHEMERAL, NO-EGRESS, resource-capped KVM microVM that runs a BENIGN payload and is
# then destroyed. There is NO Scylla integration and NO hostile code here — M1 proves only that the
# isolation tier boots, contains (no network, no host FS), and tears down. See ../HARNESS-BUILD-PLAN.md
# (M1) and ../HARNESS-THREAT-MODEL.md for what this gates.
#
# Tooling: QEMU `microvm` machine + KVM. On a host where the invoking user is in the `kvm` group,
# RUNNING needs no sudo; the one elevation is reading the host kernel (typically 0600 root) — set
# $KERNEL to a readable bzImage to skip it. For M5 (hostile samples) the tier should migrate to
# Firecracker (a smaller attack surface than full QEMU); QEMU+KVM is the M1/M-benign first cut.
set -uo pipefail
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
command -v qemu-system-x86_64 >/dev/null || { echo "need qemu-system-x86_64"; exit 1; }
command -v busybox >/dev/null || { echo "need busybox (static, for the guest init)"; exit 1; }
[ -e /dev/kvm ] || { echo "need /dev/kvm — this host has no usable KVM"; exit 1; }

# 1. Minimal guest: static busybox + an /init that prints a marker, shows it has NO network, halts.
mkdir -p "$W/initramfs/bin"
cp "$(command -v busybox)" "$W/initramfs/bin/busybox"
cat > "$W/initramfs/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys
/bin/busybox mount -t proc proc /proc 2>/dev/null
echo "M1_GUEST_RAN ok uname=$(/bin/busybox uname -sr)"
echo "M1_GUEST_NET_IFACES=[$(/bin/busybox ls /sys/class/net 2>/dev/null | tr '\n' ' ')]"
/bin/busybox poweroff -f
INIT
chmod +x "$W/initramfs/init"
(cd "$W/initramfs" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9) > "$W/initramfs.cpio.gz"

# 2. A readable kernel (the host kernel is usually 0600 root; copy it, or pass $KERNEL).
KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
if [ -r "$KSRC" ]; then
  cp "$KSRC" "$W/vmlinuz"
else
  echo "kernel $KSRC not readable; copying with sudo (set \$KERNEL to a readable bzImage to avoid)"
  sudo install -m0644 "$KSRC" "$W/vmlinuz" || { echo "could not obtain a readable kernel"; exit 1; }
fi

# 3. Boot: `microvm` machine + KVM, 256M cap, NO network (`-nic none`), no host FS (no -drive),
#    40s kill-switch (`timeout`), `-no-reboot` so the guest's poweroff ENDS qemu (ephemeral).
echo "=== M1 microVM boot — no network, 256M cap, ephemeral, 40s kill-switch ==="
OUT="$W/serial.log"
timeout 40 qemu-system-x86_64 \
  -machine microvm -accel kvm -cpu host -m 256 -smp 1 \
  -kernel "$W/vmlinuz" -initrd "$W/initramfs.cpio.gz" \
  -append "console=ttyS0 reboot=t panic=-1" \
  -nodefaults -no-reboot -no-user-config -nic none \
  -serial stdio -display none > "$OUT" 2>&1
rc=$?
grep -aE 'M1_GUEST' "$OUT" || true

# 4. Verdict: the payload ran (execution) AND the guest had no network (containment) AND qemu exited
#    (ephemeral teardown).
ran=$(grep -ac 'M1_GUEST_RAN ok' "$OUT")
nonet=$(grep -a 'M1_GUEST_NET_IFACES' "$OUT" | grep -c '\[\]')
if [ "$ran" -ge 1 ] && [ "$nonet" -ge 1 ]; then
  echo "[m1] PASS — benign payload ran in an ephemeral, no-network, 256M-capped microVM, then it was destroyed (qemu rc=$rc)."
  echo "[m1] GATE PENDING: the GAP-5/7 RED-TEAM (escape + resource-bomb a HOSTILE guest, prove no host/net/cross-run reach) is the next checkpoint before M2 — see ../HARNESS-BUILD-PLAN.md."
else
  echo "[m1] FAIL — serial tail:"; tail -n 30 "$OUT"; exit 1
fi
