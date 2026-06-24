#!/usr/bin/env bash
# Harness M5.3 prep — observe a PERSISTENCE attempt; the ephemeral tier contains it (benign).
#
# "Persistence" is one of M5.3's named malware behavior classes. This de-risks it on a BENIGN sample: a
# program that drops a cron persistence file (/etc/cron.d/...), run inside the ephemeral Firecracker
# tier under the syscall observer. Both must hold:
#   OBSERVE  — the syscall observer captures the persistence write (openat + write to the cron path).
#   CONTAIN  — it touches NO host FS (the tier has none), and it does NOT survive: booting the same
#              image again, the dropped file is GONE (ephemeral per-run rootfs, GAP-9).
# So the harness learns the persistence mechanism a sample tried, with nothing left behind. Benign;
# no malware; no Scylla change.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.local/bin:$PATH" CC="${CC:-/usr/bin/gcc}"
FC="${FIRECRACKER:-$(command -v firecracker || echo "$HOME/.local/bin/firecracker")}"
GCC="${CC:-/usr/bin/gcc}"
for t in "$FC" busybox strace "$GCC" ldd cpio; do command -v "$t" >/dev/null || [ -x "$t" ] || { echo "need $t"; exit 1; }; done
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }
VMLINUX="${VMLINUX:-}"
if [ -z "$VMLINUX" ] || [ ! -r "$VMLINUX" ]; then
  KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"; EXV="/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux"
  [ -r "$KSRC" ] && [ -x "$EXV" ] || { echo "set \$VMLINUX (or \$KERNEL + extract-vmlinux)"; exit 1; }
  bash "$EXV" "$KSRC" > "$W/vmlinux" 2>/dev/null; VMLINUX="$W/vmlinux"
fi

cat > "$W/persist.c" <<'C'
/* Benign "persistence": drop a cron job. In the ephemeral, no-host-FS tier it touches no host and
   does not survive a reboot. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void){
    const char *p = "/etc/cron.d/scylla-persist";
    int fd = open(p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    int r = -1;
    if (fd >= 0){ const char *l = "* * * * * root /tmp/payload\n"; r = (int)write(fd, l, strlen(l)); close(fd); }
    printf("PERSIST path=%s write_rc=%d\n", p, r);
    return 0;
}
C
"$GCC" -O0 -o "$W/persist" "$W/persist.c"

IR="$W/ir"; mkdir -p "$IR/bin" "$IR/lib64" "$IR/etc/cron.d"
cp "$(command -v busybox)" "$IR/bin/busybox"; cp "$(command -v strace)" "$IR/bin/strace"; cp "$W/persist" "$IR/persist"
stage(){ ldd "$1" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' | while read -r L; do
  [ -f "$L" ] || continue; mkdir -p "$IR$(dirname "$L")"; cp -n "$L" "$IR$L" 2>/dev/null || true; done; }
stage "$(command -v strace)"; stage "$W/persist"
echo "$(cd "$IR" && find . -name '*.so*' -printf '/%h\n' | sed 's#/\.##' | sort -u | tr '\n' ':')" > "$IR/etc/ldpath"
cat > "$IR/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /tmp /etc/cron.d; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ldpath)"
# Run 2 detection: did a PRIOR boot's persistence file survive? (it must not — ephemeral)
[ -f /etc/cron.d/scylla-persist ] && echo "M5_3_PRIOR_PERSIST=PRESENT" || echo "M5_3_PRIOR_PERSIST=ABSENT"
/bin/strace -f -e trace=openat,write -o /tmp/p.s -- /persist 2>/tmp/p.err
echo "M5_3_OBSERVED_WRITE=[$($B grep -a 'cron.d/scylla-persist' /tmp/p.s 2>/dev/null | $B head -1)]"
$B reboot -f
INIT
chmod +x "$IR/init"
( cd "$IR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"
cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }, "drives": [], "network-interfaces": [] }
JSON

echo "=== boot 1: observe the persistence drop in the ephemeral tier ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/b1.log" 2>&1
grep -aE 'PERSIST|M5_3_' "$W/b1.log" | sed 's/^/    /'
echo "=== boot 2: SAME image — the dropped file must be GONE (ephemeral) ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/b2.log" 2>&1
grep -aE 'M5_3_PRIOR_PERSIST' "$W/b2.log" | sed 's/^/    /'

echo "============================================================"
ok=1
grep -aq 'M5_3_OBSERVED_WRITE=\[.*cron.d/scylla-persist' "$W/b1.log" \
  && echo "[m5.3-persist] OBSERVE — the syscall observer captured the persistence write to /etc/cron.d/scylla-persist." \
  || { echo "[m5.3-persist] FAIL observe"; ok=0; }
{ grep -aq 'M5_3_PRIOR_PERSIST=ABSENT' "$W/b2.log" && ! grep -aq 'M5_3_PRIOR_PERSIST=PRESENT' "$W/b2.log"; } \
  && echo "[m5.3-persist] CONTAIN — run 2 saw NO prior persistence file: the drop did not survive (ephemeral), and touched no host FS." \
  || { echo "[m5.3-persist] FAIL contain — persistence survived across runs"; ok=0; }
if [ "$ok" -eq 1 ]; then
  echo "[m5.3-persist] PASS — the harness OBSERVED the persistence mechanism a sample tried, and the ephemeral no-host-FS tier left nothing behind. M5.3's persistence behavior class is de-risked on benign."
  exit 0
else exit 1; fi
