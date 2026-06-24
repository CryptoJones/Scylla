#!/usr/bin/env bash
# Harness M3 — the IN-GUEST OBSERVER.
#
# Inside the contained microVM (M1) it runs a BENIGN dynamically-linked sample under the glibc loader's
# own `LD_DEBUG=bindings` + `LD_BIND_NOW`, which makes the loader resolve and LOG every import — i.e. it
# reconstructs the sample's RESOLVED IAT at runtime (exactly what a dynamic IAT-rebuilder emits for a
# packed/stripped sample whose imports static analysis can't see). The observer turns that into a JSON
# trace, frames it (m3-frame, matching channel.rs), and writes it on the M2 one-way serial channel. The
# host then reads it back through the bounded validator (`m2-read`) and checks the recovered IAT against
# ground truth. Gate: on a benign sample with a known IAT, the observer recovers it, over the channel.
#
# Still NO hostile execution (a benign sample), NO Scylla integration (M4 wires it through collaborate).
# Set $KERNEL to a readable bzImage.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE_DIR="$(cd "$HERE/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}" CXX="${CXX:-/usr/bin/g++}"
GCC="${CC:-/usr/bin/gcc}"
for t in qemu-system-x86_64 busybox "$GCC" readelf ldd cpio; do command -v "$t" >/dev/null || { echo "need $t"; exit 1; }; done
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }

echo "=== build: host reader (channel.rs) + the benign sample + the in-guest framer ==="
( cd "$SPIKE_DIR" && cargo build -q ) || { echo "spike build failed"; exit 1; }
BIN="$SPIKE_DIR/target/debug/dynamic-analysis-seam-spike"
"$GCC" -O0 -o "$W/sample" "$HERE/sample.c"   || { echo "sample build failed"; exit 1; }
"$GCC" -O2 -o "$W/m3-frame" "$HERE/m3-frame.c" || { echo "m3-frame build failed"; exit 1; }

# Ground truth: the sample's known API calls — the IAT the observer must recover.
GROUND="getpid puts snprintf"
echo "ground-truth imports the observer must recover: $GROUND"

# The sample's dynamic loader + libc (the guest must carry exactly these).
INTERP="$(readelf -l "$W/sample" | sed -n 's/.*interpreter: \(.*\)\]/\1/p' | tr -d ' ')"
LIBC="$(ldd "$W/sample" | sed -n 's/.*=> \(.*libc\.so[^ ]*\).*/\1/p' | head -1)"
echo "interp=$INTERP  libc=$LIBC"
[ -r "$INTERP" ] && [ -r "$LIBC" ] || { echo "could not locate ld.so/libc"; exit 1; }

# Assemble the initramfs: busybox(static) + sample(dyn) + m3-frame(dyn) + ld.so + libc + /init.
mkdir -p "$W/ir/bin" "$W/ir/etc" "$W/ir$(dirname "$INTERP")" "$W/ir$(dirname "$LIBC")"
cp "$(command -v busybox)" "$W/ir/bin/busybox"
cp "$W/sample" "$W/ir/sample"; cp "$W/m3-frame" "$W/ir/m3-frame"
cp "$INTERP" "$W/ir$INTERP"; cp "$LIBC" "$W/ir$LIBC"
echo "$(dirname "$LIBC")" > "$W/ir/etc/ld-path"   # data-drives the guest's LD_LIBRARY_PATH (no ld.so.cache)
cat > "$W/ir/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc 2>/dev/null
export LD_LIBRARY_PATH="$($B cat /etc/ld-path)"
echo "GUEST: observer running the benign sample under the loader (LD_DEBUG=bindings) to recover its resolved IAT"
export LD_DEBUG=bindings LD_BIND_NOW=1
/sample 2>/binds >/dev/null
unset LD_DEBUG
SYMS=$($B grep "normal symbol" /binds | $B grep -E "binding file [^ ]*/sample" | $B sed "s/.*normal symbol .//; s/'.*//" | $B sort -u)
J='{"edges":['
f=1
for s in $SYMS; do [ $f -eq 1 ] && f=0 || J="$J,"; J="$J{\"from\":\"sample\",\"to\":\"$s\",\"confidence\":95}"; done
J="$J]}"
echo "GUEST: recovered $($B echo $SYMS | $B wc -w) resolved imports; emitting the framed trace on the channel:"
echo "$J" | /m3-frame
echo "GUEST: done"
$B poweroff -f
INIT
chmod +x "$W/ir/init"

KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
if [ -r "$KSRC" ]; then cp "$KSRC" "$W/vmlinuz"; else echo "kernel $KSRC not readable; set \$KERNEL"; exit 1; fi
( cd "$W/ir" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/ir.cpio.gz"

echo "=== boot the contained microVM (no net, no host FS, 256M cap) — observer emits on serial ==="
timeout 40 qemu-system-x86_64 -machine microvm -accel kvm -cpu host -m 256 -smp 1 \
  -kernel "$W/vmlinuz" -initrd "$W/ir.cpio.gz" -append "console=ttyS0 reboot=t panic=-1" \
  -nodefaults -no-reboot -no-user-config -nic none -serial stdio -display none > "$W/serial.log" 2>&1
grep -aE 'GUEST:' "$W/serial.log" | sed 's/^/    /'

echo "=== host reads the channel through the bounded validator (channel.rs / m2-read) ==="
"$BIN" m2-read < "$W/serial.log" | tee "$W/edges.txt"
RECOVERED="$(grep -oE '> [A-Za-z_][A-Za-z0-9_]*' "$W/edges.txt" | sed 's/> //' | sort -u)"
echo "recovered over the validated channel: $(echo $RECOVERED | tr '\n' ' ')"

echo "============================================================"
miss=0
for g in $GROUND; do
  if echo "$RECOVERED" | grep -qx "$g"; then echo "[m3] recovered  $g"; else echo "[m3] MISSING    $g"; miss=1; fi
done
if [ $miss -eq 0 ]; then
  echo "[m3] PASS — the in-guest observer recovered the benign sample's resolved IAT ($GROUND) inside the contained microVM, and the host read it over the bounded, validated M2 channel. M4 (wire through collaborate, WRONG=0) is unblocked."
  exit 0
else
  echo "[m3] FAIL — a ground-truth import was not recovered over the channel."; exit 1
fi
