#!/usr/bin/env bash
# Harness M5.3 prep — observe a NETWORK-BEACON attempt while the tier CONTAINS it (benign).
#
# "Network beaconing attempts" is one of M5.3's named malware behavior classes. This de-risks it on a
# BENIGN sample: a program that tries to connect() to an external IP, run inside the no-egress
# Firecracker tier under the syscall observer. Two things must both hold:
#   OBSERVE   — the syscall observer captures the beacon attempt (socket()/connect() with the target).
#   CONTAIN   — the connect FAILS (no NIC/route in the tier) → no egress, exactly as M1/M5.0 require.
# So the harness can SEE a beaconing attempt and still PREVENT it. Benign; no malware; no Scylla change.
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

cat > "$W/beacon.c" <<'C'
/* Benign "beacon": try to phone home to 8.8.8.8:443. In the no-egress tier this MUST fail. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
int main(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; a.sin_family = AF_INET; a.sin_port = htons(443);
    inet_pton(AF_INET, "8.8.8.8", &a.sin_addr);
    int r = connect(s, (struct sockaddr*)&a, sizeof a);
    printf("BEACON connect rc=%d\n", r);
    return 0;
}
C
"$GCC" -O0 -o "$W/beacon" "$W/beacon.c"

IR="$W/ir"; mkdir -p "$IR/bin" "$IR/lib64" "$IR/etc"
cp "$(command -v busybox)" "$IR/bin/busybox"; cp "$(command -v strace)" "$IR/bin/strace"; cp "$W/beacon" "$IR/beacon"
stage(){ ldd "$1" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' | while read -r L; do
  [ -f "$L" ] || continue; mkdir -p "$IR$(dirname "$L")"; cp -n "$L" "$IR$L" 2>/dev/null || true; done; }
stage "$(command -v strace)"; stage "$W/beacon"
echo "$(cd "$IR" && find . -name '*.so*' -printf '/%h\n' | sed 's#/\.##' | sort -u | tr '\n' ':')" > "$IR/etc/ldpath"
cat > "$IR/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /tmp; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ldpath)"
echo "M5_3_NET_IFACES=[$($B ls /sys/class/net 2>/dev/null | $B tr '\n' ' ')]"
/bin/strace -f -e trace=socket,connect -o /tmp/b.s -- /beacon 2>/tmp/b.err
echo "M5_3_OBSERVED_CONNECT=[$($B grep -a 'connect(' /tmp/b.s 2>/dev/null | $B head -1)]"
$B reboot -f
INIT
chmod +x "$IR/init"
( cd "$IR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"
cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }, "drives": [], "network-interfaces": [] }
JSON

echo "=== boot the no-egress Firecracker tier; observe a benign beacon attempt ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/serial.log" 2>&1
grep -aE 'BEACON|M5_3_' "$W/serial.log" | sed 's/^/    /'

echo "============================================================"
ifaces="$(grep -a 'M5_3_NET_IFACES' "$W/serial.log" | sed 's/.*=\[//;s/\].*//')"
observed_connect="$(grep -a 'M5_3_OBSERVED_CONNECT' "$W/serial.log")"
beacon_rc="$(grep -a 'BEACON connect rc=' "$W/serial.log" | sed 's/.*rc=//')"
ok=1
# CONTAIN: no real NIC, and the connect did NOT succeed (rc != 0 → -1, blocked).
{ [ "$(echo "$ifaces" | tr ' ' '\n' | grep -vE '^(lo)?$' | grep -cE '.')" -eq 0 ] && [ "${beacon_rc:-0}" != "0" ]; } \
  && echo "[m5.3-beacon] CONTAIN — no NIC (ifaces=[$ifaces]); the beacon connect FAILED (rc=$beacon_rc): no egress." \
  || { echo "[m5.3-beacon] FAIL contain — ifaces=[$ifaces] beacon_rc=$beacon_rc"; ok=0; }
# OBSERVE: the syscall observer captured the connect() to 8.8.8.8.
echo "$observed_connect" | grep -q '8.8.8.8' \
  && echo "[m5.3-beacon] OBSERVE  — the syscall observer captured the beacon attempt: $observed_connect" \
  || { echo "[m5.3-beacon] FAIL observe — connect() to 8.8.8.8 not captured"; ok=0; }
if [ "$ok" -eq 1 ]; then
  echo "[m5.3-beacon] PASS — the harness OBSERVED a network-beacon attempt AND the tier CONTAINED it (no egress). M5.3's beaconing behavior class is de-risked on a benign sample."
  exit 0
else exit 1; fi
