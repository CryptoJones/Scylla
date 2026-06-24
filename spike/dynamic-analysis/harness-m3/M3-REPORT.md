# Harness M3 — the in-guest observer: **DONE** (benign-sample gate PASS)

M1 contains a hostile guest; M2 carries a recorded trace out over one bounded, validated channel.
**M3 is what runs *inside* the VM to produce that trace** — and its gate is: on a benign sample with a
known IAT, the observer recovers it, reproducibly, end-to-end over the channel. **PASS.**

## The observer: the loader *is* the IAT rebuilder

The seam spike's proven win is a **resolved IAT** — the import table a dynamic producer rebuilds for a
packed/stripped sample whose imports static analysis can't see. The minimal, dependency-free way to get
the *real* thing on Linux: run the sample under the glibc loader with **`LD_DEBUG=bindings`** +
**`LD_BIND_NOW=1`**, which makes `ld.so` resolve *every* import eagerly and log each binding. The
observer (the guest `/init`) filters the bindings *originating in the sample*, turns them into a JSON
trace, and pipes it to **`m3-frame`** (a tiny C framer whose base64 + FNV-1a-64 match `channel.rs`
byte-for-byte) which writes the **M2 frame on serial**.

So the chain is real and complete: **execute (in the sandbox) → observe (resolved IAT) → channel (M2)
→ validate (host)**. The observer + framer are dynamically linked and share the sample's `ld.so`/`libc`
in the initramfs (`LD_LIBRARY_PATH` data-driven from `/etc/ld-path`, since there's no `ld.so.cache`);
busybox is static. Still inside M1's tier: **no network, no host FS, 256 M cap, ephemeral.**

## Measured (`m3-observe.sh`, on the real microVM)

```
GUEST: observer running the benign sample under the loader (LD_DEBUG=bindings) to recover its resolved IAT
GUEST: recovered 11 resolved imports; emitting the framed trace on the channel
[m2] ACCEPTED 11 observed edge(s) — bounded + validated, never eval'd:
[m2]   sample -> getpid / puts / snprintf / calloc / free / malloc / realloc / __libc_start_main / ...
[m3] recovered  getpid   [m3] recovered  puts   [m3] recovered  snprintf
[m3] PASS — the in-guest observer recovered the benign sample's resolved IAT, read over the validated M2 channel.
```

The observer recovered the sample's full runtime IAT (its three known API calls `getpid`/`puts`/
`snprintf`, plus the libc startup/`__stack_chk_fail`/allocator bindings); the host read it back through
`channel.rs` (`m2-read`) and confirmed all three ground-truth imports. The recovered set is
**loader-deterministic** (re-running yields the same set → reproducible), and the run is within budget
(boots + observes + halts in seconds, under the 40 s kill-switch).

## Scope — what this proves, and the honest limit

- **Proves the M3 gate:** a real in-guest observer recovers a benign sample's known IAT and delivers it
  over the contained, validated channel — the producer half end-to-end, executing a real program in the
  tier (a *benign* one).
- **The honest limit (still benign-only):** `LD_DEBUG` relies on the sample **cooperating** with the
  stock loader. Real packed/anti-analysis malware may be statically linked or custom-packed (no glibc
  PLT to log) or may detect/suppress `LD_DEBUG`. The **general** observer for *uncooperative* samples is
  instruction-level tracing — **ptrace / QEMU-user trace / Frida** (the build plan's M3 recommendation) —
  which observes resolution without the sample's cooperation. That generalization rides with **M5**
  (hostile samples), behind the M1 red-team re-run + external pen-test. M3 here establishes the seam and
  the gate on a benign sample, exactly as planned (the IAT a real run emits, now from a *real run*).
- **GAP-8 (evasion) remains open and inherent:** a sample that detects the harness can emit a
  *valid-but-partial/lying* trace. M2 guarantees it can't break the host; **DD-007/DD-027 provenance +
  confidence** must record that dynamic coverage is partial, so the matcher never treats it as ground
  truth. That weighting is M4.

## Next — M4

Wire `read_trace`'s `Vec<ObservedEdge>` through `scylla-merge::collaborate`, stamped
`Provenance { producer: "dynamic", confidence }` (DD-007), behind the engine port as an opt-in second
producer; gate: on benign samples the dynamic producer enriches the static model with **`WRONG = 0`**
preserved end-to-end.

Reproduce: `KERNEL=<readable-bzImage> ./m3-observe.sh` (exit 0 = gate pass).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
