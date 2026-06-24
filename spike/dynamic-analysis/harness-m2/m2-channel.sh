#!/usr/bin/env bash
# Harness M2 — the ONE-WAY OBSERVATION CHANNEL, end-to-end on the real tier.
#
# M1's tier has NO egress and NO host FS, so a recorded trace leaves the guest over exactly one
# bounded channel: the guest writes a framed trace to its serial console (ttyS0); the host reads that
# captured serial through the bounded, validating reader (../src/channel.rs). This demo proves the
# channel works on the real microVM, that the reader finds the frame amid kernel console noise, and
# that a corrupted channel is QUARANTINED. The adversarial GAP-6 gate is `cargo test` (channel::gap6) —
# 19 cases asserting no malformed/oversized/nested trace can panic, hang, or OOM the host reader.
#
# Still NO Scylla integration and NO hostile execution: the guest is benign and emits a canned trace
# (an in-guest OBSERVER that produces a real trace is M3). Set $KERNEL to a readable bzImage.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE_DIR="$(cd "$HERE/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}" CXX="${CXX:-/usr/bin/g++}"
command -v qemu-system-x86_64 >/dev/null || { echo "need qemu-system-x86_64"; exit 1; }
command -v busybox >/dev/null || { echo "need a static busybox"; exit 1; }
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }

echo "=== build the host-side reader (channel.rs) + the m2-make/m2-read subcommands ==="
( cd "$SPIKE_DIR" && cargo build -q ) || { echo "build failed"; exit 1; }
BIN="$SPIKE_DIR/target/debug/dynamic-analysis-seam-spike"

# 1. The trace an in-guest observer would emit (here, canned — M3 produces a real one).
"$BIN" m2-make > "$W/trace"
echo "--- the frame the guest will write to serial ---"; sed 's/^/    /' "$W/trace"

# 2. Readable kernel.
KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
if [ -r "$KSRC" ]; then cp "$KSRC" "$W/vmlinuz"; else echo "kernel $KSRC not readable; set \$KERNEL"; exit 1; fi

# 3. Benign guest: emit console noise, then the trace frame, on ttyS0; halt. No net, no host FS.
mkdir -p "$W/ir/bin"; cp "$(command -v busybox)" "$W/ir/bin/busybox"; cp "$W/trace" "$W/ir/trace"
cat > "$W/ir/init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc 2>/dev/null
echo "GUEST: (observer finished) emitting the recorded trace on the one-way channel:"
$B cat /trace
echo "GUEST: done"
$B poweroff -f
INIT
chmod +x "$W/ir/init"
( cd "$W/ir" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$W/ir.cpio.gz"

# 4. Boot the contained microVM, capture the serial stream.
echo "=== boot the contained microVM (no net, no host FS, 256M cap) — capturing the channel ==="
timeout 40 qemu-system-x86_64 -machine microvm -accel kvm -cpu host -m 256 -smp 1 \
  -kernel "$W/vmlinuz" -initrd "$W/ir.cpio.gz" -append "console=ttyS0 reboot=t panic=-1" \
  -nodefaults -no-reboot -no-user-config -nic none -serial stdio -display none > "$W/serial.log" 2>&1

# 5. Positive: the host reader must find + accept the frame buried in the kernel/console noise.
echo "=== host reader on the captured serial (positive) ==="
if "$BIN" m2-read < "$W/serial.log"; then POS=ok; else POS=fail; fi

# 6. Negative: corrupt the channel (flip the checksum) — the reader must QUARANTINE it, not trust it.
echo "=== host reader on a CORRUPTED channel (negative) ==="
sed 's/fnv=[0-9a-f]*/fnv=0000000000000000/' "$W/serial.log" > "$W/serial.bad"
if "$BIN" m2-read < "$W/serial.bad" 2>&1; then NEG=accepted; else NEG=quarantined; fi

echo "============================================================"
[ "$POS" = ok ] && echo "[m2] PASS positive — a valid trace was read off the REAL serial channel; console noise ignored." || { echo "[m2] FAIL positive"; exit 1; }
[ "$NEG" = quarantined ] && echo "[m2] PASS negative — a corrupted channel was QUARANTINED (exit 2), not trusted." || { echo "[m2] FAIL negative — a corrupted channel was accepted"; exit 1; }
echo "[m2] CHANNEL OK — one-way serial in, bounded+validated, corruption rejected. GAP-6 fuzz: \`cargo test\` (channel::gap6, 19 cases)."
