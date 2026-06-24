# Harness M5.3 prep — observe a persistence attempt; the ephemeral tier contains it: **PASS** (benign)

"Persistence" is one of M5.3's named malware behavior classes. De-risked on a **benign** sample
(`m5_3-persistence.sh`): a program that drops a cron job (`/etc/cron.d/scylla-persist`), run in the
ephemeral Firecracker tier under the syscall observer.

## Measured

```
# boot 1
M5_3_PRIOR_PERSIST=ABSENT
PERSIST path=/etc/cron.d/scylla-persist write_rc=28
M5_3_OBSERVED_WRITE=[openat(AT_FDCWD, "/etc/cron.d/scylla-persist", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3]
# boot 2 (same image)
M5_3_PRIOR_PERSIST=ABSENT      <- the drop did NOT survive
```

- **OBSERVE:** the syscall observer captured the persistence write — the exact cron path
  (`/etc/cron.d/scylla-persist`) the sample tried to install. So the analyst learns the *mechanism*.
- **CONTAIN:** booting the same image again, the dropped file is **gone** (`PRIOR_PERSIST=ABSENT`) —
  the ephemeral per-run rootfs (GAP-9) means persistence can't survive a run, and with no host FS
  mounted (M1) it never touched the host in the first place.

So the harness **learns the persistence mechanism a sample tried, with nothing left behind** — the
intel without the foothold.

## For M5.3

Persistence is a named M5.3 behavior class; this shows the observe+contain pair for it on benign code.
At M5.3, real malware's persistence attempts are recorded (the cron/systemd/autostart path it targeted)
as partial-coverage `producer="dynamic"` observations (DD-007), while the ephemeral no-host-FS tier
guarantees they neither persist nor reach the host. GAP-8 (a sample that detects the sandbox and skips
persistence) is inherent and recorded. Real malware still needs the M5.3 infrastructure
(HARNESS-M5-PLAN.md).

Reproduce: `VMLINUX=<uncompressed> ./m5_3-persistence.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
