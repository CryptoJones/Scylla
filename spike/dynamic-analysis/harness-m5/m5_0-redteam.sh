#!/usr/bin/env bash
# Harness M5.0 GATE — the GAP-5/7 RED TEAM re-run on the FIRECRACKER tier.
#
# The same adversarial gate as M1's `m1-redteam.sh`, against the migrated Firecracker tier: boot guests
# that DELIBERATELY attack the containment knobs and assert FROM THE HOST that nothing escaped. If the
# QEMU tier held (it did, 16/16) and the Firecracker tier — a smaller VMM attack surface — also holds,
# M5's recommended tier is de-risked on SYNTHETIC attacks. Still NOT real malware (that is M5.3, on an
# isolated node + external pen-test). Contained BY the boundary under test (no net, no drives, 256M/1
# vcpu, kill-switch) on a many-core/GBs-free host.
#
# Firecracker exit semantics differ from QEMU: a guest that resets (triple-fault `reboot`) makes
# Firecracker EXIT (rc != 124); a guest that never halts is reaped by the `timeout` kill-switch
# (rc == 124). Needs `firecracker` (PATH/$FIRECRACKER), a static busybox, and an uncompressed $VMLINUX
# (or $KERNEL + extract-vmlinux).
set -uo pipefail
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
FC="${FIRECRACKER:-$(command -v firecracker || echo "$HOME/.local/bin/firecracker")}"
[ -x "$FC" ] || { echo "need firecracker"; exit 1; }
command -v busybox >/dev/null || { echo "need a static busybox"; exit 1; }
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }
VMLINUX="${VMLINUX:-}"
if [ -z "$VMLINUX" ] || [ ! -r "$VMLINUX" ]; then
  KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"; EXV="/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux"
  [ -r "$KSRC" ] && [ -x "$EXV" ] || { echo "set \$VMLINUX (or \$KERNEL + extract-vmlinux)"; exit 1; }
  bash "$EXV" "$KSRC" > "$W/vmlinux" 2>/dev/null; VMLINUX="$W/vmlinux"
fi
echo "=== M5.0 GATE red team on FIRECRACKER — $($FC --version|head -1), nproc=$(nproc), MemAvailable=$(awk '/MemAvailable/{printf "%d MB",$2/1024}' /proc/meminfo) ==="
FAILS=0
pass(){ echo "[RT] PASS  $1 — $2"; }
fail(){ echo "[RT] FAIL  $1 — $2"; FAILS=$((FAILS+1)); }

build(){ # $1=init script, $2=out.cpio.gz
  local d="$W/ir"; rm -rf "$d"; mkdir -p "$d/bin"; cp "$(command -v busybox)" "$d/bin/busybox"
  cp "$1" "$d/init"; chmod +x "$d/init"
  ( cd "$d" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$2"
}
fc_boot(){ # $1=initrd, $2=timeout → serial to $3 ; returns rc
  cat > "$W/cfg.json" <<JSON
{ "boot-source": { "kernel_image_path": "$VMLINUX", "initrd_path": "$1",
    "boot_args": "console=ttyS0 reboot=t panic=1 pci=off rdinit=/init" },
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 256 }, "drives": [], "network-interfaces": [] }
JSON
  timeout "$2" "$FC" --no-api --config-file "$W/cfg.json" > "$3" 2>&1
  return $?
}
HB="$W/hb"; MEM="$W/mem"; MON=""
mon_start(){ : >"$HB"; : >"$MEM"; ( while :; do date +%s.%N >>"$HB"; awk '/MemAvailable/{print $2}' /proc/meminfo >>"$MEM"; sleep 0.3; done ) & MON=$!; }
mon_stop(){ [ -n "$MON" ] && { kill "$MON" 2>/dev/null; wait "$MON" 2>/dev/null; MON=""; }; }
max_gap(){ awk 'NR>1{d=$1-p; if(d>m)m=d}{p=$1}END{printf "%.2f",m+0}' "$HB"; }
min_mem(){ sort -n "$MEM" 2>/dev/null | head -1; }
CANARY="$W/host-canary"; echo "untouched-$(date +%s)" > "$CANARY"; CB="$(cat "$CANARY")"

# A — GAP-5 escape probe (net, host FS, devices); halts via triple-fault reboot.
cat > "$W/a.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /mnt; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
echo "RT_A_BEGIN escape-probe (firecracker)"
echo "RT_A_NET_IFACES=[$($B ls /sys/class/net 2>/dev/null | $B tr '\n' ' ')]"
$B ip link set eth0 up 2>/dev/null; $B udhcpc -i eth0 -n -q 2>/dev/null
( echo x | $B nc -w 2 169.254.169.254 80 ) >/dev/null 2>&1 && echo "RT_A_CONNECT=OPEN" || echo "RT_A_CONNECT=blocked"
echo "RT_A_BLOCKDEVS=[$($B ls /dev 2>/dev/null | $B grep -E '^(vd|sd|nvme|xvd|hd[a-z])' | $B tr '\n' ' ')]"
$B mount /dev/vda /mnt 2>/dev/null && echo "RT_A_MOUNT_VDA=OK" || echo "RT_A_MOUNT_VDA=blocked"
$B mount -t 9p -o trans=virtio host /mnt 2>/dev/null && echo "RT_A_MOUNT_9P=OK" || echo "RT_A_MOUNT_9P=blocked"
echo "RT_A_PCI_DEVS=[$($B ls /sys/bus/pci/devices 2>/dev/null | $B tr '\n' ' ')]"
echo "RT_A_VIRTIO_DEVS=[$($B ls /sys/bus/virtio/devices 2>/dev/null | $B tr '\n' ' ')]"
[ -e /dev/vsock ] && echo "RT_A_VSOCK=present" || echo "RT_A_VSOCK=absent"
echo "RT_A_DONE"; $B reboot -f
INIT
build "$W/a.init" "$W/a.cpio.gz"; A="$W/a.log"; fc_boot "$W/a.cpio.gz" 30 "$A"; arc=$?
grep -aE 'RT_A_' "$A" | sed 's/^/    /'
ifaces="$(grep -a RT_A_NET_IFACES "$A" | sed 's/.*=\[//;s/\].*//')"
[ "$(echo "$ifaces" | tr ' ' '\n' | grep -vE '^(lo)?$' | grep -cE '.')" -eq 0 ] && pass "A.net-ifaces" "no NIC (ifaces=[$ifaces])" || fail "A.net-ifaces" "a NIC appeared: [$ifaces]"
grep -aq 'RT_A_CONNECT=blocked' "$A" && pass "A.net-egress" "egress blocked (incl. 169.254.169.254 metadata)" || fail "A.net-egress" "a connection succeeded"
[ -z "$(grep -a RT_A_BLOCKDEVS "$A" | sed 's/.*=\[//;s/\].*//' | tr -d ' ')" ] && pass "A.block-devs" "no host block devices" || fail "A.block-devs" "block device(s) visible"
grep -aq 'RT_A_MOUNT_VDA=blocked' "$A" && grep -aq 'RT_A_MOUNT_9P=blocked' "$A" && pass "A.host-fs" "vda + 9p mounts blocked (no host FS)" || fail "A.host-fs" "a host-FS mount succeeded"
[ -z "$(grep -a RT_A_PCI_DEVS "$A" | sed 's/.*=\[//;s/\].*//' | tr -d ' ')" ] && pass "A.no-pci" "no PCI devices (Firecracker has no PCI bus)" || fail "A.no-pci" "PCI device(s) present"
grep -aq 'RT_A_VSOCK=absent' "$A" && pass "A.vsock" "no vsock channel" || fail "A.vsock" "vsock present"
[ "$(cat "$CANARY")" = "$CB" ] && pass "A.host-canary" "host canary untouched" || fail "A.host-canary" "HOST CANARY MODIFIED"
{ grep -aq 'RT_A_DONE' "$A" && [ "$arc" -ne 124 ]; } && pass "A.ephemeral" "probe completed + Firecracker exited (rc=$arc, not the kill-switch)" || fail "A.ephemeral" "probe didn't complete/exit (rc=$arc)"

# B — GAP-7 CPU kill-switch (spin forever; only timeout stops it → rc==124).
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho RT_B_BEGIN spin\nwhile : ; do : ; done\n' > "$W/b.init"
build "$W/b.init" "$W/b.cpio.gz"; B="$W/b.log"
mon_start; fc_boot "$W/b.cpio.gz" 15 "$B"; brc=$?; mon_stop; bgap="$(max_gap)"
echo "    RT_B rc=$brc host-heartbeat-max-gap=${bgap}s"
[ "$brc" -eq 124 ] && pass "B.kill-switch" "unstoppable spinner reaped by the wall-clock kill-switch (rc=124)" || fail "B.kill-switch" "spinner not reaped (rc=$brc)"
awk -v g="$bgap" 'BEGIN{exit !(g<3)}' && pass "B.host-alive" "host responsive during spin (gap ${bgap}s; guest capped at 1 of $(nproc) vCPUs)" || fail "B.host-alive" "host stalled (gap ${bgap}s)"

# C — GAP-7 memory cap (balloon; OOM INSIDE the VM; host RAM untouched).
cat > "$W/c.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox; $B mount -t proc proc /proc 2>/dev/null; $B mkdir -p /m; $B mount -t tmpfs -o size=1024m none /m
echo "RT_C_BEGIN mem-balloon"
i=0; while : ; do $B dd if=/dev/zero of="/m/f$i" bs=1M count=16 2>/dev/null || break; i=$((i+1)); done
echo "RT_C_END reached=$((i*16))MB"; $B reboot -f
INIT
build "$W/c.init" "$W/c.cpio.gz"; C="$W/c.log"
MB="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
mon_start; fc_boot "$W/c.cpio.gz" 30 "$C"; crc=$?; mon_stop
MM="$(min_mem)"; oom=$(grep -aciE 'out of memory|oom-kill|killed process' "$C"); drop=$(( (MB-${MM:-$MB})/1024 ))
echo "    RT_C rc=$crc host-MemAvailable before=$((MB/1024))MB min=$(( ${MM:-0}/1024 ))MB drop=${drop}MB oom-markers=$oom"
awk -v d="$drop" 'BEGIN{exit !(d<700)}' && pass "C.host-ram" "guest balloon did NOT consume host RAM (drop ${drop}MB, bounded by the 256M cap)" || fail "C.host-ram" "host RAM dropped ${drop}MB"
[ "$crc" -ne 124 ] && pass "C.contained" "guest OOM'd inside the VM + Firecracker exited (rc=$crc); host fine" || fail "C.contained" "VM not reaped (rc=$crc)"

# D — GAP-7 fork bomb (never halts → timeout reaps; host proc table flat).
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho RT_D_BEGIN fork-bomb\nwhile : ; do /bin/busybox sleep 300 & done\n' > "$W/d.init"
build "$W/d.init" "$W/d.cpio.gz"; D="$W/d.log"
HP0=$(ls /proc | grep -c '^[0-9]')
mon_start; fc_boot "$W/d.cpio.gz" 15 "$D"; drc=$?; mon_stop
HP1=$(ls /proc | grep -c '^[0-9]'); dgap="$(max_gap)"
echo "    RT_D rc=$drc host-procs before=$HP0 after=$HP1 heartbeat-max-gap=${dgap}s"
[ "$drc" -eq 124 ] && pass "D.reaped" "fork-bomb VM reaped by the kill-switch (rc=124)" || fail "D.reaped" "not reaped (rc=$drc)"
awk -v a="$HP1" -v b="$HP0" 'BEGIN{exit !((a-b)<50)}' && pass "D.host-proctable" "fork-bomb confined to the VM (host procs $HP0→$HP1)" || fail "D.host-proctable" "host proc table grew by $((HP1-HP0))"
awk -v g="$dgap" 'BEGIN{exit !(g<3)}' && pass "D.host-alive" "host responsive during fork-bomb (gap ${dgap}s)" || fail "D.host-alive" "host stalled (gap ${dgap}s)"

# E — GAP-9 ephemerality (same image booted twice; run 2 must not see run 1's writes).
cat > "$W/e.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox; $B mount -t proc proc /proc 2>/dev/null
[ -f /PWNED ] && echo "RT_E_RESULT=LEAK" || echo "RT_E_RESULT=CLEAN"
$B sh -c 'echo pwned > /PWNED' 2>/dev/null; $B reboot -f
INIT
build "$W/e.init" "$W/e.cpio.gz"; fc_boot "$W/e.cpio.gz" 15 "$W/e1.log"; fc_boot "$W/e.cpio.gz" 15 "$W/e2.log"
e1="$(grep -a RT_E_RESULT "$W/e1.log" | sed 's/RT_E_RESULT=//')"; e2="$(grep -a RT_E_RESULT "$W/e2.log" | sed 's/RT_E_RESULT=//')"
echo "    RT_E run1=[$e1] run2=[$e2]"
{ grep -aq 'RT_E_RESULT=CLEAN' "$W/e1.log" && grep -aq 'RT_E_RESULT=CLEAN' "$W/e2.log" && ! grep -aq 'RT_E_RESULT=LEAK' "$W/e2.log"; } \
  && pass "E.ephemeral" "fresh rootfs each boot — no cross-run persistence" || fail "E.ephemeral" "state persisted across runs"

echo "============================================================"
if [ "$FAILS" -eq 0 ]; then
  echo "[RT] FIRECRACKER GATE PASS — the migrated tier contained every synthetic hostile guest (no escape, no host exhaustion, reaped within budget, ephemeral), same as the QEMU tier — on a SMALLER VMM attack surface. M5.0 de-risked."
  echo "[RT] Real malware (M5.3) still requires an isolated node + a malware corpus + an external pen-test (HARNESS-M5-PLAN.md)."
  exit 0
else
  echo "[RT] FIRECRACKER GATE FAIL — $FAILS assertion(s) failed; do NOT advance."; exit 1
fi
