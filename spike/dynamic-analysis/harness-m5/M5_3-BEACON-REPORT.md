# Harness M5.3 prep — observe a network-beacon attempt while the tier contains it: **PASS** (benign)

"Network beaconing attempts" is one of M5.3's named malware behavior classes. This de-risks it on a
**benign** sample: a program that tries to `connect()` to `8.8.8.8:443`, run inside the **no-egress
Firecracker tier** under the syscall observer. Both properties must hold at once.

## Measured (inside the tier)

```
M5_3_NET_IFACES=[lo ]
BEACON connect rc=-1
M5_3_OBSERVED_CONNECT=[connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH]
[m5.3-beacon] CONTAIN — no NIC (ifaces=[lo]); the beacon connect FAILED (rc=-1): no egress.
[m5.3-beacon] OBSERVE  — the syscall observer captured the beacon attempt.
[m5.3-beacon] PASS
```

- **OBSERVE:** the syscall observer captured the full beacon attempt — `connect()` to `8.8.8.8:443` —
  including the target address and port. So the harness *sees* a beaconing attempt as a first-class
  observation (a behavioral edge a dynamic producer can record, stamped `producer="dynamic"`).
- **CONTAIN:** the tier has no NIC (loopback only) and the `connect()` returned `-1 ENETUNREACH` — the
  beacon **could not phone home**. This is M1/M5.0's no-egress guarantee, now exercised by a program
  that actively *tries* to use the network.

So the harness can **observe a beaconing attempt and still prevent it** — exactly what running a
malware sample requires: you learn what it tried to do (intel) without letting it actually do it.

## Why it matters for M5.3

M5.3 introduces real malware "one behavior class at a time", and **network beaconing** is one of them.
This shows the observe+contain pair works for that class on benign code: the no-egress tier blocks the
egress (GAP-5 network), and the syscall observer records the attempt (the intel). When real malware
beacons at M5.3, the analyst gets the C2 endpoint it *tried* to reach, with **zero packets leaving the
box**. The observation is partial-coverage `producer="dynamic"` (DD-007), down-rankable, never ground
truth; GAP-8 (a sample that detects no-net and stays quiet) is inherent and recorded.

Still benign; no malware; no Scylla core change. Real malware needs the M5.3 infrastructure
(HARNESS-M5-PLAN.md).

Reproduce: `VMLINUX=<uncompressed> ./m5_3-beacon.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
