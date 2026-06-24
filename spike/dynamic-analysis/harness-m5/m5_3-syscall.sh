#!/usr/bin/env bash
# Harness M5.3 prep — the SYSCALL-level observer, inside the Firecracker tier (packing-resistant).
#
# The packing finding (M5_1-PACKED-FINDING.md) showed the PLT-interception observer (M5.1) is defeated
# by a packer (no static PLT), while a SYSCALL trace survives. M5.3 (real malware, routinely packed)
# therefore needs a syscall-level observer. This DE-RISKS that observer on BENIGN samples, INSIDE the
# Firecracker tier (M5.0): it straces both a normal and a UPX-packed benign binary in the guest and
# confirms it recovers their behavior (getpid + write) from BOTH — including the packed one, where the
# PLT observer recovered nothing. Benign-only; no malware. Real malware + anti-trace hardening is M5.3
# proper (isolated node + jailer + corpus + external pen-test, HARNESS-M5-PLAN.md).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.local/bin:$PATH" CC="${CC:-/usr/bin/gcc}"
FC="${FIRECRACKER:-$(command -v firecracker || echo "$HOME/.local/bin/firecracker")}"
GCC="${CC:-/usr/bin/gcc}"
for t in "$FC" busybox strace upx "$GCC" ldd cpio; do command -v "$t" >/dev/null || [ -x "$t" ] || { echo "need $t"; exit 1; }; done
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }
VMLINUX="${VMLINUX:-}"
if [ -z "$VMLINUX" ] || [ ! -r "$VMLINUX" ]; then
  KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"; EXV="/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux"
  [ -r "$KSRC" ] && [ -x "$EXV" ] || { echo "set \$VMLINUX (or \$KERNEL + extract-vmlinux)"; exit 1; }
  bash "$EXV" "$KSRC" > "$W/vmlinux" 2>/dev/null; VMLINUX="$W/vmlinux"
fi

cat > "$W/sample.c" <<'C'
#include <stdio.h>
#include <unistd.h>
int main(void){ printf("pid=%d\n",(int)getpid()); return 0; }
C
"$GCC" -O0 -o "$W/sample" "$W/sample.c"
cp "$W/sample" "$W/sample_packed"; upx -q --best "$W/sample_packed" >/dev/null 2>&1

IR="$W/ir"; mkdir -p "$IR/bin" "$IR/lib64" "$IR/etc"
cp "$(command -v busybox)" "$IR/bin/busybox"; cp "$(command -v strace)" "$IR/bin/strace"
cp "$W/sample" "$IR/sample"; cp "$W/sample_packed" "$IR/sample_packed"
stage(){ ldd "$1" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' | while read -r L; do
  [ -f "$L" ] || continue; mkdir -p "$IR$(dirname "$L")"; cp -n "$L" "$IR$L" 2>/dev/null || true; done; }
stage "$(command -v strace)"; stage "$W/sample"
LIBDIRS="$(cd "$IR" && find . -name '*.so*' -printf '/%h\n' | sed 's#/\.##' | sort -u | tr '\n' ':')"
echo "$LIBDIRS" > "$IR/etc/ldpath"
cat > "$IR/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /tmp; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ldpath)"
for bin in sample sample_packed; do
  /bin/strace -f -e trace=getpid,write -o /tmp/$bin.s -- /$bin >/dev/null 2>/tmp/$bin.err || true
  gp=$($B grep -c 'getpid' /tmp/$bin.s 2>/dev/null)
  wr=$($B grep -c 'write(1' /tmp/$bin.s 2>/dev/null)
  echo "M5_3_TRACE bin=$bin getpid=$gp write1=$wr"
done
$B reboot -f
INIT
chmod +x "$IR/init"
( cd "$IR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"
cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }, "drives": [], "network-interfaces": [] }
JSON

echo "=== boot Firecracker tier; the SYSCALL observer straces a normal + a PACKED benign binary ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/serial.log" 2>&1
grep -aE 'M5_3_TRACE' "$W/serial.log" | sed 's/^/    /'

echo "============================================================"
fails=0
for bin in sample sample_packed; do
  line="$(grep -a "M5_3_TRACE bin=$bin " "$W/serial.log" | tail -1)"
  gp=$(echo "$line" | sed -n 's/.*getpid=\([0-9]*\).*/\1/p'); wr=$(echo "$line" | sed -n 's/.*write1=\([0-9]*\).*/\1/p')
  if [ "${gp:-0}" -ge 1 ] && [ "${wr:-0}" -ge 1 ]; then
    echo "[m5.3] recovered behavior from $bin (getpid=$gp write1=$wr) via syscall trace in the tier"
  else
    echo "[m5.3] MISSING behavior from $bin (getpid=${gp:-0} write1=${wr:-0})"; fails=$((fails+1))
  fi
done
if [ "$fails" -eq 0 ]; then
  echo "[m5.3] PASS — the syscall-level observer recovered behavior from BOTH the normal AND the PACKED binary inside the Firecracker tier (where PLT interception was defeated by packing). M5.3's packing-resistant observer is de-risked on benign samples."
  exit 0
else
  echo "[m5.3] FAIL — $fails sample(s) yielded no syscall behavior."; exit 1
fi
