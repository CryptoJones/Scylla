#!/usr/bin/env bash
# Dynamic-analysis harness — MILESTONE 1 GATE: the GAP-5 / GAP-7 RED TEAM.
#
# m1-microvm.sh proved the tier boots/contains/tears-down a *cooperative* (benign) guest. THIS proves
# it contains a HOSTILE one: it boots guests that DELIBERATELY ATTEMPT to break the containment knobs —
#   GAP-5 (escape):   reach the host network, the host filesystem/devices, or the hypervisor.
#   GAP-7 (exhaust):  spin / balloon / fork-bomb to starve the host or beat the kill-switch.
#   GAP-9 (persist):  leave state behind for the next run.
# and then ASSERTS, FROM THE HOST, that none of it reached past the VM boundary. PASS gates M2.
#
# This is adversarial testing of OUR OWN sandbox with SYNTHETIC attacks — NOT real malware (that is M5,
# which additionally needs an isolated node + an external pen-test). The attacks are contained BY the
# very boundary under test: no NIC, no -drive, -m 256/-smp 1, a wall-clock kill-switch. The host has
# many cores + GBs free, so a guest pinned to 1 vCPU / 256 MB cannot starve it — which is the point.
#
# Tooling: QEMU `microvm` + KVM (user in the `kvm` group → no elevation to RUN). The one elevation is
# reading the 0600-root host kernel; set $KERNEL to a readable bzImage to skip it (see m1-microvm.sh).
set -uo pipefail

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
command -v qemu-system-x86_64 >/dev/null || { echo "need qemu-system-x86_64"; exit 1; }
command -v busybox >/dev/null || { echo "need a static busybox"; exit 1; }
[ -e /dev/kvm ] || { echo "need /dev/kvm"; exit 1; }

# Readable kernel (host kernel is usually 0600 root).
KSRC="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
if [ -r "$KSRC" ]; then cp "$KSRC" "$W/vmlinuz"
else echo "kernel $KSRC not readable; set \$KERNEL to a readable bzImage (e.g. copy it once)"; exit 1; fi

# Learn this host's `timeout`-killed exit code (GNU & uutils both use 124, but measure, don't assume).
timeout 1 sleep 5 >/dev/null 2>&1; TKILL=$?
echo "=== M1 GATE red team — host timeout-kill code=$TKILL, host nproc=$(nproc), host MemAvailable=$(awk '/MemAvailable/{printf "%d MB",$2/1024}' /proc/meminfo) ==="

QEMU_COMMON=(-machine microvm -accel kvm -cpu host -m 256 -smp 1 -nodefaults -no-reboot -no-user-config -nic none -serial stdio -display none)
APPEND="console=ttyS0 reboot=t panic=-1"
FAILS=0
pass(){ echo "[RT] PASS  $1 — $2"; }
fail(){ echo "[RT] FAIL  $1 — $2"; FAILS=$((FAILS+1)); }

# Build an initramfs from an /init script ($1) into $2.
build(){
  local init="$1" out="$2" d="$W/ir"
  rm -rf "$d"; mkdir -p "$d/bin"; cp "$(command -v busybox)" "$d/bin/busybox"
  cp "$init" "$d/init"; chmod +x "$d/init"
  ( cd "$d" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) > "$out"
}
# Boot $1(initramfs) with timeout $2 → serial to $3, returns qemu/timeout rc.
boot(){
  timeout "$2" qemu-system-x86_64 "${QEMU_COMMON[@]}" -kernel "$W/vmlinuz" -initrd "$1" -append "$APPEND" > "$3" 2>&1
  return $?
}

# Host-side activity monitor (proves the host stayed alive during resource bombs).
HB="$W/hb"; MEM="$W/mem"; MON=""
mon_start(){ : >"$HB"; : >"$MEM"; ( while :; do date +%s.%N >>"$HB"; awk '/MemAvailable/{print $2}' /proc/meminfo >>"$MEM"; sleep 0.3; done ) & MON=$!; }
mon_stop(){ [ -n "$MON" ] && { kill "$MON" 2>/dev/null; wait "$MON" 2>/dev/null; MON=""; }; }
max_gap(){ awk 'NR>1{d=$1-p; if(d>m)m=d}{p=$1}END{printf "%.2f",m+0}' "$HB"; }      # max seconds between heartbeats
min_mem(){ sort -n "$MEM" 2>/dev/null | head -1; }                                  # min host MemAvailable (kB) seen

# Host canary — a file the guest must never be able to touch (it has no host FS at all).
CANARY="$W/host-canary"; echo "untouched-$(date +%s)" > "$CANARY"; CANARY_BEFORE="$(cat "$CANARY")"

#############################################################################################
# SCENARIO A — GAP-5 ESCAPE PROBE: attack network egress, host FS/block devices, virtio/vsock.
#############################################################################################
cat > "$W/a.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mkdir -p /proc /sys /mnt; $B mount -t proc proc /proc 2>/dev/null; $B mount -t sysfs sys /sys 2>/dev/null
echo "RT_A_BEGIN escape-probe"
echo "RT_A_NET_IFACES=[$($B ls /sys/class/net 2>/dev/null | $B tr '\n' ' ')]"
$B ip link set eth0 up 2>/dev/null; $B udhcpc -i eth0 -n -q 2>/dev/null
( echo x | $B nc -w 2 10.0.2.2 53 ) >/dev/null 2>&1 && echo "RT_A_CONNECT_HOSTGW=OPEN" || echo "RT_A_CONNECT_HOSTGW=blocked"
( echo x | $B nc -w 2 8.8.8.8 53 ) >/dev/null 2>&1 && echo "RT_A_CONNECT_PUBLIC=OPEN" || echo "RT_A_CONNECT_PUBLIC=blocked"
echo "RT_A_BLOCKDEVS=[$($B ls /dev 2>/dev/null | $B grep -E '^(vd|sd|nvme|xvd|hd[a-z])' | $B tr '\n' ' ')]"
echo "RT_A_PARTITIONS=[$($B sed -n '3,$p' /proc/partitions 2>/dev/null | $B awk '{print $4}' | $B tr '\n' ' ')]"
$B mount /dev/vda /mnt 2>/dev/null && echo "RT_A_MOUNT_VDA=OK" || echo "RT_A_MOUNT_VDA=blocked"
$B mount -t 9p -o trans=virtio,version=9p2000.L host /mnt 2>/dev/null && echo "RT_A_MOUNT_9P=OK" || echo "RT_A_MOUNT_9P=blocked"
$B mount -t virtiofs myfs /mnt 2>/dev/null && echo "RT_A_MOUNT_VIRTIOFS=OK" || echo "RT_A_MOUNT_VIRTIOFS=blocked"
echo "RT_A_PCI_DEVS=[$($B ls /sys/bus/pci/devices 2>/dev/null | $B tr '\n' ' ')]"
echo "RT_A_VIRTIO_DEVS=[$($B ls /sys/bus/virtio/devices 2>/dev/null | $B tr '\n' ' ')]"
[ -e /dev/vsock ] && echo "RT_A_VSOCK=present" || echo "RT_A_VSOCK=absent"
[ -e /dev/vhost-vsock ] && echo "RT_A_VHOST_VSOCK=present" || echo "RT_A_VHOST_VSOCK=absent"
echo "RT_A_HV=[$($B grep -o hypervisor /proc/cpuinfo 2>/dev/null | $B head -1)]"
echo "RT_A_DONE"; $B poweroff -f
INIT
build "$W/a.init" "$W/a.cpio.gz"; A="$W/a.log"; boot "$W/a.cpio.gz" 30 "$A"; arc=$?
grep -aE 'RT_A_' "$A" | sed 's/^/    /'
ifaces="$(grep -a RT_A_NET_IFACES "$A" | sed 's/.*=\[//;s/\].*//')"
realnic=$(echo "$ifaces" | tr ' ' '\n' | grep -vE '^(lo)?$' | grep -cE '.')
[ "$realnic" -eq 0 ] && pass "A.net-ifaces" "no NIC present (ifaces=[$ifaces]; loopback-only)" || fail "A.net-ifaces" "a real NIC appeared: [$ifaces]"
grep -aq 'RT_A_CONNECT_HOSTGW=blocked' "$A" && grep -aq 'RT_A_CONNECT_PUBLIC=blocked' "$A" && pass "A.net-egress" "host-gw + public connects both blocked (no egress)" || fail "A.net-egress" "a network connection succeeded"
[ -z "$(grep -a RT_A_BLOCKDEVS "$A" | sed 's/.*=\[//;s/\].*//' | tr -d ' ')" ] && pass "A.block-devs" "no host block devices visible" || fail "A.block-devs" "host block device(s) visible"
grep -aq 'RT_A_MOUNT_VDA=blocked' "$A" && grep -aq 'RT_A_MOUNT_9P=blocked' "$A" && grep -aq 'RT_A_MOUNT_VIRTIOFS=blocked' "$A" && pass "A.host-fs" "vda / 9p / virtiofs mounts all blocked (no host FS)" || fail "A.host-fs" "a host-FS mount succeeded"
grep -aq 'RT_A_VSOCK=absent' "$A" && grep -aq 'RT_A_VHOST_VSOCK=absent' "$A" && pass "A.vsock" "no vsock channel to the host" || fail "A.vsock" "a vsock device is present"
[ "$(cat "$CANARY")" = "$CANARY_BEFORE" ] && pass "A.host-canary" "host canary untouched (guest reached no host FS)" || fail "A.host-canary" "HOST CANARY MODIFIED"
grep -aq 'RT_A_DONE' "$A" && pass "A.completed" "probe ran to completion in the VM" || fail "A.completed" "probe did not complete"

#############################################################################################
# SCENARIO B — GAP-7 CPU KILL-SWITCH: a guest that spins forever; only the wall-clock can stop it.
#############################################################################################
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho "RT_B_BEGIN cpu-spin-forever"\nwhile : ; do : ; done\n' > "$W/b.init"
build "$W/b.init" "$W/b.cpio.gz"; B="$W/b.log"
mon_start; boot "$W/b.cpio.gz" 15 "$B"; brc=$?; mon_stop
bgap="$(max_gap)"
echo "    RT_B rc=$brc  host-heartbeat-max-gap=${bgap}s"
[ "$brc" -eq "$TKILL" ] && pass "B.kill-switch" "unstoppable spinner reaped by the wall-clock kill-switch (rc=$brc)" || fail "B.kill-switch" "spinner not reaped by the kill-switch (rc=$brc, expected $TKILL)"
awk -v g="$bgap" 'BEGIN{exit !(g<3)}' && pass "B.host-alive" "host stayed responsive during the spin (max heartbeat gap ${bgap}s; guest capped at 1 of $(nproc) vCPUs)" || fail "B.host-alive" "host stalled during the spin (gap ${bgap}s)"

#############################################################################################
# SCENARIO C — GAP-7 MEMORY CAP: a guest that balloons; must OOM INSIDE the VM, host RAM untouched.
#############################################################################################
cat > "$W/c.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc 2>/dev/null; $B mkdir -p /m; $B mount -t tmpfs -o size=1024m none /m
echo "RT_C_BEGIN mem-balloon tmpfs=1024m on a 256M VM"
i=0
while : ; do
  $B dd if=/dev/zero of="/m/f$i" bs=1M count=16 2>/dev/null || { echo "RT_C_ALLOC_STOPPED_AT=${i}x16MB"; break; }
  i=$(( i + 1 )); echo "RT_C_ALLOC=$(( i * 16 ))MB"
done
echo "RT_C_END reached=$(( i * 16 ))MB"; $B poweroff -f
INIT
build "$W/c.init" "$W/c.cpio.gz"; C="$W/c.log"
MEMBEFORE="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
mon_start; boot "$W/c.cpio.gz" 30 "$C"; crc=$?; mon_stop
MEMMIN="$(min_mem)"; reached="$(grep -a RT_C_ALLOC= "$C" | tail -1 | sed 's/.*=//')"
oom=$(grep -aciE 'out of memory|oom-kill|killed process|panic' "$C")
dropMB=$(( (MEMBEFORE - ${MEMMIN:-$MEMBEFORE}) / 1024 ))
echo "    RT_C rc=$crc  guest-reached=${reached:-?}  host-MemAvailable: before=$((MEMBEFORE/1024))MB min-during=$(( ${MEMMIN:-0}/1024 ))MB drop=${dropMB}MB  guest-oom-markers=$oom"
awk -v d="$dropMB" 'BEGIN{exit !(d<700)}' && pass "C.host-ram" "guest balloon did NOT consume host RAM (host drop ${dropMB}MB << guest demand; bounded by qemu's 256M+overhead)" || fail "C.host-ram" "host RAM dropped ${dropMB}MB — the cap leaked"
{ [ "$oom" -ge 1 ] || awk -v r="${reached:-0}" 'BEGIN{exit !(r<260)}'; } && pass "C.guest-capped" "guest hit the 256M wall inside the VM (reached ${reached:-?}, oom-markers=$oom)" || fail "C.guest-capped" "guest allocated past the cap (reached ${reached}MB)"

#############################################################################################
# SCENARIO D — GAP-7 FORK BOMB: spawn until the guest can't; host process table must not balloon.
#############################################################################################
printf '#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc 2>/dev/null\necho "RT_D_BEGIN fork-bomb"\nn=0\nwhile : ; do /bin/busybox sleep 300 & n=$(( n + 1 )); [ $(( n %% 250 )) -eq 0 ] && echo "RT_D_SPAWNED=$n"; done\n' > "$W/d.init"
build "$W/d.init" "$W/d.cpio.gz"; D="$W/d.log"
HPROC_BEFORE=$(ls /proc | grep -c '^[0-9]')
mon_start; boot "$W/d.cpio.gz" 15 "$D"; drc=$?; mon_stop
HPROC_AFTER=$(ls /proc | grep -c '^[0-9]'); dgap="$(max_gap)"
spawned="$(grep -a RT_D_SPAWNED "$D" | tail -1 | sed 's/.*=//')"
echo "    RT_D rc=$drc  guest-spawned>=${spawned:-?}  host-procs: before=$HPROC_BEFORE after=$HPROC_AFTER  host-heartbeat-max-gap=${dgap}s"
[ "$drc" -eq "$TKILL" ] && pass "D.reaped" "fork-bomb VM reaped by the kill-switch (rc=$drc)" || fail "D.reaped" "fork-bomb VM not reaped (rc=$drc)"
awk -v a="$HPROC_AFTER" -v b="$HPROC_BEFORE" 'BEGIN{exit !((a-b)<50)}' && pass "D.host-proctable" "guest fork-bomb confined to the VM (host procs $HPROC_BEFORE→$HPROC_AFTER; the thousands of guest procs never reached the host)" || fail "D.host-proctable" "host process table grew by $((HPROC_AFTER-HPROC_BEFORE))"
awk -v g="$dgap" 'BEGIN{exit !(g<3)}' && pass "D.host-alive" "host stayed responsive during the fork-bomb (max heartbeat gap ${dgap}s)" || fail "D.host-alive" "host stalled during the fork-bomb (gap ${dgap}s)"

#############################################################################################
# SCENARIO E — GAP-9 EPHEMERALITY: boot the SAME image twice; run 2 must not see run 1's writes.
#############################################################################################
cat > "$W/e.init" <<'INIT'
#!/bin/busybox sh
B=/bin/busybox; $B mount -t proc proc /proc 2>/dev/null
[ -f /PWNED_BY_PRIOR_RUN ] && echo "RT_E_RESULT=LEAK prior-run-state-survived" || echo "RT_E_RESULT=CLEAN no-prior-state"
$B sh -c 'echo pwned > /PWNED_BY_PRIOR_RUN' 2>/dev/null
echo "RT_E_DONE"; $B poweroff -f
INIT
build "$W/e.init" "$W/e.cpio.gz"; E1="$W/e1.log"; E2="$W/e2.log"
boot "$W/e.cpio.gz" 15 "$E1" >/dev/null; boot "$W/e.cpio.gz" 15 "$E2" >/dev/null
e1="$(grep -a RT_E_RESULT "$E1" | sed 's/RT_E_RESULT=//')"; e2="$(grep -a RT_E_RESULT "$E2" | sed 's/RT_E_RESULT=//')"
echo "    RT_E run1=[$e1]  run2=[$e2]"
{ grep -aq 'RT_E_RESULT=CLEAN' "$E1" && grep -aq 'RT_E_RESULT=CLEAN' "$E2" && ! grep -aq 'RT_E_RESULT=LEAK' "$E2"; } \
  && pass "E.ephemeral" "fresh rootfs each boot — run 1's writes did not survive into run 2 (no cross-run persistence)" \
  || fail "E.ephemeral" "state persisted across runs"

#############################################################################################
echo "============================================================================"
if [ "$FAILS" -eq 0 ]; then
  echo "[RT] GATE PASS — the M1 microVM contained every synthetic hostile guest: no escape (net/FS/device/vsock), no host exhaustion, reaped within budget, ephemeral."
  echo "[RT] This clears the GAP-5/GAP-7 gate for the CONFIGURED containment on SYNTHETIC attacks. A determined attacker with a QEMU device 0-day (GAP-5 residual) is the domain of M5 — external pen-test + the Firecracker migration (smaller host attack surface)."
  exit 0
else
  echo "[RT] GATE FAIL — $FAILS containment assertion(s) failed above. M2 stays blocked. DO NOT proceed."
  exit 1
fi
