#!/usr/bin/env bash
# Harness M5.1 — the UNCOOPERATIVE in-guest observer (generalize M3 beyond LD_DEBUG).
#
# M3 recovered the resolved IAT via the glibc loader's LD_DEBUG=bindings — which needs a *cooperative*
# sample + loader (a statically-linked / custom-packed / LD_DEBUG-suppressing binary defeats it). M5.1
# recovers the same IAT by **external ptrace observation** (ltrace intercepts PLT calls), with LD_DEBUG
# UNSET — so it works on an UNcooperative sample. Run inside the Firecracker tier (M5.0); the recovered
# IAT crosses the M2 channel and the host validates + checks ground truth.
#
# Still benign-only (a benign sample) + contained. Real malware is M5.3 (isolated node + pen-test).
# Needs firecracker (PATH/$FIRECRACKER), ltrace, gcc, a static busybox, $VMLINUX (or $KERNEL+extract).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; M3="$(cd "$HERE/../harness-m3" && pwd)"; SPIKE="$(cd "$HERE/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}"
FC="${FIRECRACKER:-$(command -v firecracker || echo "$HOME/.local/bin/firecracker")}"
GCC="${CC:-/usr/bin/gcc}"
for t in "$FC" busybox ltrace "$GCC" readelf ldd cpio; do command -v "$t" >/dev/null || [ -x "$t" ] || { echo "need $t"; exit 1; }; done
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }
VMLINUX="${VMLINUX:-}"
if [ -z "$VMLINUX" ] || [ ! -r "$VMLINUX" ]; then
  KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"; EXV="/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux"
  [ -r "$KSRC" ] && [ -x "$EXV" ] || { echo "set \$VMLINUX (or \$KERNEL + extract-vmlinux)"; exit 1; }
  bash "$EXV" "$KSRC" > "$W/vmlinux" 2>/dev/null; VMLINUX="$W/vmlinux"
fi

echo "=== build the benign sample + the M2 framer, host-side reader ==="
( cd "$SPIKE" && cargo build -q ) || { echo "spike build failed"; exit 1; }
BIN="$SPIKE/target/debug/dynamic-analysis-seam-spike"
"$GCC" -O0 -o "$W/sample" "$M3/sample.c"
"$GCC" -O2 -o "$W/m3-frame" "$M3/m3-frame.c"
GROUND="getpid puts snprintf"

IR="$W/ir"; mkdir -p "$IR/bin" "$IR/lib64"
cp "$(command -v busybox)" "$IR/bin/busybox"
cp "$(command -v ltrace)" "$IR/bin/ltrace"
cp "$W/sample" "$IR/sample"; cp "$W/m3-frame" "$IR/m3-frame"
# Stage every shared lib ltrace + the sample + the framer need (preserving absolute paths), + ld.so.
stage(){ ldd "$1" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' | while read -r L; do
  [ -f "$L" ] || continue; mkdir -p "$IR$(dirname "$L")"; cp -n "$L" "$IR$L" 2>/dev/null || true; done; }
stage "$(command -v ltrace)"; stage "$W/sample"; stage "$W/m3-frame"
# union of lib dirs for LD_LIBRARY_PATH (no ld.so.cache in the guest)
LIBDIRS="$(cd "$IR" && find . -name '*.so*' -printf '/%h\n' | sed 's#/\.##' | sort -u | tr '\n' ':')"
echo "$LIBDIRS" > "$IR/etc-ldpath" 2>/dev/null || { mkdir -p "$IR/etc"; echo "$LIBDIRS" > "$IR/etc/ldpath"; }
mkdir -p "$IR/etc"; echo "$LIBDIRS" > "$IR/etc/ldpath"

cat > "$IR/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /tmp; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ldpath)"
# UNCOOPERATIVE: LD_DEBUG is explicitly unset — recovery is by external ptrace (ltrace), not the loader.
unset LD_DEBUG
echo "GUEST(M5.1): ltrace-observing the benign sample (LD_DEBUG unset; external PLT interception)"
/bin/ltrace -f -e '*' -o /tmp/lt.out -- /sample >/dev/null 2>/tmp/lt.err || true
SYMS=$($B grep -oE 'sample->[A-Za-z_][A-Za-z0-9_]*' /tmp/lt.out 2>/dev/null | $B sed 's/sample->//' | $B sort -u)
J='{"edges":['
f=1
for s in $SYMS; do [ $f -eq 1 ] && f=0 || J="$J,"; J="$J{\"from\":\"sample\",\"to\":\"$s\",\"confidence\":92}"; done
J="$J]}"
echo "GUEST(M5.1): recovered $($B echo $SYMS | $B wc -w) imports via ptrace; emitting framed trace:"
echo "$J" | /m3-frame
echo "GUEST(M5.1): done"
$B reboot -f
INIT
chmod +x "$IR/init"
( cd "$IR" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/initrd.cpio.gz"

cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$W/initrd.cpio.gz",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }, "drives": [], "network-interfaces": [] }
JSON
echo "=== boot Firecracker tier; the UNCOOPERATIVE ltrace observer runs inside ==="
timeout 40 "$FC" --no-api --config-file "$W/cfg.json" > "$W/serial.log" 2>&1
grep -aE 'GUEST\(M5.1\)' "$W/serial.log" | sed 's/^/    /'

echo "=== host reads the channel through the bounded validator (channel.rs / m2-read) ==="
"$BIN" m2-read < "$W/serial.log" | tee "$W/edges.txt"
RECOVERED="$(grep -oE '> [A-Za-z_][A-Za-z0-9_]*' "$W/edges.txt" | sed 's/> //' | sort -u)"
echo "recovered (uncooperative, LD_DEBUG unset) over the validated channel: $(echo $RECOVERED | tr '\n' ' ')"
echo "============================================================"
miss=0
for g in $GROUND; do echo "$RECOVERED" | grep -qx "$g" && echo "[m5.1] recovered  $g" || { echo "[m5.1] MISSING    $g"; miss=1; }; done
if [ $miss -eq 0 ]; then
  echo "[m5.1] PASS — the UNCOOPERATIVE observer (ltrace / external ptrace, LD_DEBUG unset) recovered the benign sample's resolved IAT inside the Firecracker tier, read over the validated M2 channel. Works where M3's loader approach needs cooperation. M5.2 (benign uplift) next."
  exit 0
else
  echo "[m5.1] FAIL — a ground-truth import was not recovered."; exit 1
fi
