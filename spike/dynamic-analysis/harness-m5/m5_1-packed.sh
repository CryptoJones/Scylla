#!/usr/bin/env bash
# Harness M5.1 follow-on — PACKING defeats the PLT-interception observer; syscall-tracing survives.
#
# M5.1's observer (ltrace / external PLT interception) recovers a sample's resolved IAT without loader
# cooperation. But a PACKED sample (UPX) defeats it: the packer's stub has no PLT — the real import
# table only materializes in memory AFTER the stub decompresses + jumps to the original at runtime, so
# breakpoints placed on the (empty) static PLT never fire. This demonstrates that honestly on a BENIGN
# binary, and shows the packing-RESISTANT layer: a SYSCALL trace (strace / ptrace-syscall), because the
# unpacked code still makes syscalls. The finding informs M5's observer design (M5_1-PACKED-FINDING.md):
# the dynamic harness needs a syscall-level observer for packed/hostile samples, not just PLT interception.
#
# Benign-only. Needs gcc, upx, ltrace, strace. NO Scylla integration; NO malware.
set -uo pipefail
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
GCC="${CC:-/usr/bin/gcc}"
for t in "$GCC" upx ltrace strace nm readelf; do command -v "$t" >/dev/null || { echo "need $t (upx: apt install upx-ucl)"; exit 1; }; done

cat > "$W/sample.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void){ char b[64]; snprintf(b,sizeof b,"pid=%d len=%zu",(int)getpid(),strlen("scylla")); puts(b); return 0; }
C
"$GCC" -O0 -o "$W/sample" "$W/sample.c"
cp "$W/sample" "$W/sample_packed"; upx -q --best "$W/sample_packed" >/dev/null 2>&1
echo "=== sizes ==="; ls -l "$W/sample" "$W/sample_packed" | awk '{print $5, $NF}'

echo "=== (1) STATIC view of the PACKED binary — imports hidden by the packer ==="
echo "unpacked UND dynsyms: $(readelf --dyn-syms "$W/sample" 2>/dev/null | grep -c UND)   packed UND dynsyms: $(readelf --dyn-syms "$W/sample_packed" 2>/dev/null | grep -c UND)"

echo "=== (2) DYNAMIC, PLT-interception (ltrace, M5.1's observer) on the PACKED binary — ALSO defeated ==="
n_lt=$(env -u LD_DEBUG ltrace -e '*' -o /dev/stdout "$W/sample_packed" 2>/dev/null | grep -cE 'sample_packed->')
echo "ltrace recovered $n_lt of the sample's own PLT calls from the packed binary (the PLT only exists post-unpack)"

echo "=== (3) DYNAMIC, SYSCALL-level (strace) on the PACKED binary — SURVIVES packing ==="
strace -f -e trace=all -o "$W/p.strace" "$W/sample_packed" >/dev/null 2>&1
n_sys=$(grep -oE '[a-z_]+\(' "$W/p.strace" | sed 's/(//' | sort -u | wc -l)
echo "strace recovered $n_sys distinct syscalls; behavioral evidence the unpacked program ran:"
grep -E 'getpid|write\(1' "$W/p.strace" | head -2 | sed 's/^/    /'

echo "============================================================"
ok=1
[ "$(readelf --dyn-syms "$W/sample_packed" 2>/dev/null | grep -c UND)" -eq 0 ] || { echo "[m5.1b] note: packer left imports visible (weaker packer)"; }
[ "$n_lt" -eq 0 ] && echo "[m5.1b] CONFIRMED — packing defeats the PLT-interception observer (ltrace recovered 0)." || { echo "[m5.1b] ltrace recovered $n_lt from packed (unexpected for UPX)"; ok=0; }
grep -q 'getpid' "$W/p.strace" && echo "[m5.1b] CONFIRMED — syscall tracing SURVIVES packing (recovered the unpacked program's behavior)." || { echo "[m5.1b] FAIL — strace recovered no behavior"; ok=0; }
echo "[m5.1b] FINDING: the dynamic harness needs a SYSCALL-level observer for packed/hostile samples; PLT interception (M5.1) is the benign-IAT path. See M5_1-PACKED-FINDING.md."
[ "$ok" -eq 1 ]
