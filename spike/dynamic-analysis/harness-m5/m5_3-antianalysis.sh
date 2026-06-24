#!/usr/bin/env bash
# Harness M5.3 prep — ANTI-ANALYSIS (tracer detection): an honest GAP-8 finding.
#
# "Anti-analysis" is one of M5.3's named behavior classes. A benign sample reads /proc/self/status's
# TracerPid to detect a ptrace-based observer, run in the tier BOTH ways:
#   under the syscall observer (strace) → the sample sees TracerPid != 0 → it KNOWS it's traced.
#   without the observer                → TracerPid == 0 (control).
# So an in-guest ptrace observer (M5.1 ltrace / M5.3 strace) is DETECTABLE — GAP-8 (evasion) is real:
# a sample that detects the harness can lie or stay benign. The harness still OBSERVES the detection
# behavior (the read of /proc/self/status), and the mitigations are: (a) stealthier OUT-OF-GUEST
# observation (QEMU-TCG instruction trace / hypervisor introspection — no in-guest TracerPid), and
# (b) the provenance discipline — dynamic observations are partial-coverage, confidence-stamped, and
# down-ranked, NEVER ground truth (DD-007/DD-027). Benign; no malware; no Scylla change.
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

cat > "$W/aa.c" <<'C'
/* Benign anti-analysis probe: detect a ptrace-based tracer via /proc/self/status TracerPid. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    FILE *f = fopen("/proc/self/status","r"); char ln[256]; int traced=0;
    if(f){ while(fgets(ln,sizeof ln,f)){ if(strncmp(ln,"TracerPid:",10)==0) traced = atoi(ln+10)!=0; } fclose(f); }
    printf("ANTI_ANALYSIS traced=%d\n", traced);
    return 0;
}
C
"$GCC" -O0 -o "$W/aa" "$W/aa.c"

IR="$W/ir"; mkdir -p "$IR/bin" "$IR/lib64" "$IR/etc"
cp "$(command -v busybox)" "$IR/bin/busybox"; cp "$(command -v strace)" "$IR/bin/strace"; cp "$W/aa" "$IR/aa"
stage(){ ldd "$1" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' | while read -r L; do
  [ -f "$L" ] || continue; mkdir -p "$IR$(dirname "$L")"; cp -n "$L" "$IR$L" 2>/dev/null || true; done; }
stage "$(command -v strace)"; stage "$W/aa"
echo "$(cd "$IR" && find . -name '*.so*' -printf '/%h\n' | sed 's#/\.##' | sort -u | tr '\n' ':')" > "$IR/etc/ldpath"
cat > "$IR/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /tmp; $B mount -t proc proc /proc 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ldpath)"
echo "M5_3_AA_CONTROL=$(/aa | $B sed 's/.*traced=//')"          # no observer
/bin/strace -f -e trace=openat -o /tmp/aa.s -- /aa > /tmp/aa.out 2>/dev/null  # under observer
echo "M5_3_AA_TRACED=$($B sed 's/.*traced=//' /tmp/aa.out 2>/dev/null)"
echo "M5_3_AA_OBSERVED_PROBE=[$($B grep -ac 'proc/self/status' /tmp/aa.s 2>/dev/null)]"
$B reboot -f
INIT
chmod +x "$IR/init"
( cd "$IR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"
cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }, "drives": [], "network-interfaces": [] }
JSON

echo "=== boot the tier; run the anti-analysis probe with + without the ptrace observer ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/serial.log" 2>&1
grep -aE 'ANTI_ANALYSIS|M5_3_AA' "$W/serial.log" | sed 's/^/    /'

echo "============================================================"
ctrl="$(grep -a 'M5_3_AA_CONTROL=' "$W/serial.log" | tail -1 | sed 's/.*=//' | tr -dc '0-9')"
traced="$(grep -a 'M5_3_AA_TRACED=' "$W/serial.log" | tail -1 | sed 's/.*=//' | tr -dc '0-9')"
obs="$(grep -a 'M5_3_AA_OBSERVED_PROBE=' "$W/serial.log" | tail -1 | sed 's/.*=\[//;s/\].*//' | tr -dc '0-9')"
ok=1
{ [ "${ctrl:-1}" = "0" ] && [ "${traced:-0}" = "1" ]; } \
  && echo "[m5.3-aa] FINDING CONFIRMED — the in-guest ptrace observer is DETECTABLE: no-observer traced=$ctrl, under-observer traced=$traced (GAP-8 evasion is real)." \
  || { echo "[m5.3-aa] inconclusive — control=$ctrl traced=$traced (expected 0 then 1)"; ok=0; }
[ "${obs:-0}" -ge 1 ] && echo "[m5.3-aa] OBSERVE — the harness still captured the anti-analysis behavior (the /proc/self/status probe)." || { echo "[m5.3-aa] FAIL observe — probe not captured"; ok=0; }
if [ "$ok" -eq 1 ]; then
  echo "[m5.3-aa] PASS (finding) — GAP-8 demonstrated: a ptrace-based observer is detectable, and the harness sees the detection. Mitigations: (1) stealthier OUT-OF-GUEST observation (QEMU-TCG / hypervisor introspection, no in-guest TracerPid); (2) provenance down-ranking — dynamic observations stay partial-coverage + confidence-stamped, NEVER ground truth (DD-007/DD-027)."
  exit 0
else exit 1; fi
