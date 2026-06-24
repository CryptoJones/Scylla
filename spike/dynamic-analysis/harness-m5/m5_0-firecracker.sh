#!/usr/bin/env bash
# Harness M5.0 — the containment tier on FIRECRACKER (the M1 tier, migrated).
#
# M1 stood the tier up on QEMU `microvm`+KVM. M5 runs *real malware*, for which Firecracker is the
# recommended monitor — a far smaller host attack surface than full QEMU (a minimal VMM: virtio-mmio +
# serial only, no PCI/BIOS/legacy-device emulation, written in Rust, with an optional `jailer`). This
# stands the SAME containment knobs up on Firecracker and boots a BENIGN guest: ephemeral, no network
# (no `network-interfaces`), no host FS (no `drives`), capped (`vcpu_count`/`mem_size_mib`), kill-switch
# (`timeout`). Its red team is `m5_0-redteam.sh`. NO hostile code here; NO Scylla integration.
#
# Firecracker needs an UNCOMPRESSED kernel (`vmlinux`), not a bzImage: set $VMLINUX, or this extracts
# one from ${KERNEL:-/boot/vmlinuz-$(uname -r)} via the kernel's extract-vmlinux. Needs `firecracker`
# on PATH (or $FIRECRACKER) and a static busybox. The guest exits via a triple-fault `reboot` (Fire-
# cracker's clean teardown signal) — guest-reset → rc != 124; only the kill-switch yields rc == 124.
set -uo pipefail
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
FC="${FIRECRACKER:-$(command -v firecracker || echo "$HOME/.local/bin/firecracker")}"
[ -x "$FC" ] || { echo "need firecracker (set \$FIRECRACKER or install to ~/.local/bin)"; exit 1; }
command -v busybox >/dev/null || { echo "need a static busybox"; exit 1; }
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }

# An uncompressed vmlinux (Firecracker can't boot a compressed bzImage).
VMLINUX="${VMLINUX:-}"
if [ -z "$VMLINUX" ] || [ ! -r "$VMLINUX" ]; then
  KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
  EXV="/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux"
  [ -r "$KSRC" ] && [ -x "$EXV" ] || { echo "set \$VMLINUX to an uncompressed kernel (or make \$KERNEL + extract-vmlinux available)"; exit 1; }
  bash "$EXV" "$KSRC" > "$W/vmlinux" 2>/dev/null; VMLINUX="$W/vmlinux"
fi
echo "=== M5.0 Firecracker tier — fc=$($FC --version|head -1), vmlinux=$VMLINUX ==="

# Benign guest: print a marker, show it has NO network, halt (triple-fault reboot for clean exit).
mkdir -p "$W/ir/bin"; cp "$(command -v busybox)" "$W/ir/bin/busybox"
cat > "$W/ir/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys; /bin/busybox mount -t proc proc /proc 2>/dev/null
echo "FC_GUEST_RAN ok uname=$(/bin/busybox uname -sr)"
echo "FC_GUEST_NET_IFACES=[$(/bin/busybox ls /sys/class/net 2>/dev/null | /bin/busybox tr '\n' ' ')]"
/bin/busybox reboot -f
INIT
chmod +x "$W/ir/init"
( cd "$W/ir" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"

# The containment knobs as Firecracker config: NO network-interfaces, NO drives, 256M/1vcpu.
cat > "$W/config.json" <<JSON
{
  "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 256 },
  "drives": [], "network-interfaces": []
}
JSON

echo "=== boot benign guest on Firecracker — no network, no host FS, 256M cap, 30s kill-switch ==="
OUT="$W/serial.log"
timeout 30 "$FC" --no-api --config-file "$W/config.json" > "$OUT" 2>&1
rc=$?
grep -aE 'FC_GUEST' "$OUT" || true

ran=$(grep -ac 'FC_GUEST_RAN ok' "$OUT")
nonet=$(grep -a 'FC_GUEST_NET_IFACES' "$OUT" | grep -c '\[\]')
# ephemeral: Firecracker exited on the guest reset (rc != 124); the kill-switch (124) did NOT fire.
if [ "$ran" -ge 1 ] && [ "$nonet" -ge 1 ] && [ "$rc" -ne 124 ]; then
  echo "[m5.0] PASS — benign guest ran in an ephemeral, no-network, 256M-capped FIRECRACKER microVM, then it exited (rc=$rc)."
  echo "[m5.0] The M1 containment knobs carried over to Firecracker (smaller host attack surface). Gate: m5_0-redteam.sh."
else
  echo "[m5.0] FAIL (ran=$ran nonet=$nonet rc=$rc) — serial tail:"; tail -n 25 "$OUT"; exit 1
fi
