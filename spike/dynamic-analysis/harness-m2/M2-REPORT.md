# Harness M2 — the one-way observation channel: **DONE**, GAP-6 fuzz **PASS**

M1 stood up a tier that runs a hostile guest with no egress and no host FS, and its
[red team](../harness-m1/M1-REDTEAM-REPORT.md) proved it holds. **M2 is how an observation gets
*out*** of that box — over a single bounded channel the host treats as hostile input — and its gate
is the **GAP-6** fuzz: no adversarial / oversized / malformed trace may panic, hang, or OOM the host
reader. **Both are met:** the channel works end-to-end on the real microVM, and the 19-case GAP-6 fuzz
(`cargo test`, `channel::gap6`) is green.

## The channel: serial, one-way, no new attack surface

M1's tier already has `-serial stdio` and nothing else writable. So the channel is exactly that: the
guest writes a **framed trace to its serial console (`ttyS0`)**, and the host reads the captured serial
stream. It is strictly **guest→host** — the guest cannot use it to reach the host, and it adds **no new
device** to the tier (so no new GAP-5 surface). Frame:

```
SCYLLA-TRACE-V1 BEGIN
<base64 of the JSON trace, wrapped across lines>
SCYLLA-TRACE-V1 END len=<decoded-bytes> fnv=<fnv1a64-hex>
```

The JSON trace is `{"edges":[{"from":"..","to":"..","confidence":0..=100}, …]}` — the same
`ObservedEdge`s the `DynamicHarness` trait yields, so M3/M4 plug in behind it unchanged.

## The host reader (`../src/channel.rs`): treat it like a stranger's `.scylla`

`read_trace()` applies the **DD-036 total-loader discipline** — bound every dimension *before* trusting
anything, validate, then quarantine on any violation, and **never `eval`**:

1. **Bounded slurp** — reads at most `MAX_CHANNEL_BYTES` (1 MiB) + 1, ever; overflow → `TooLarge`. So a
   no-newline gigabyte or a flood of lines cannot grow host memory past ~1 MiB.
2. **Capped lines** — `MAX_LINES` (20 000), `MAX_LINE_LEN` (16 KiB).
3. **Frame located amid noise** — the BEGIN/END frame is found inside arbitrary kernel/console spam.
4. **Encoded- and decoded-size caps** (`MAX_DECODED_BYTES` 256 KiB), then std-only base64 decode.
5. **Integrity** — declared `len` + `fnv1a64` must match (corruption/forgery → reject). *(The content is
   still untrusted after this passes — integrity ≠ trust.)*
6. **Strict schema** — `serde_json` (its recursion limit turns a billion-laughs payload into a bounded
   `BadJson`, never a stack overflow); `MAX_RECORDS` (4096); every field type/length/range checked.
7. **DD-035 on display** — `sanitize_inline` strips control/escape bytes from the attacker-influenced
   names so a crafted name can't forge log structure or inject a terminal escape.

The rejection set (`ChannelReject`) is **closed and total** — every adversarial input maps to one of
them; none is a panic, hang, or OOM.

## GAP-6 gate — 19 fuzz cases, all PASS (`cargo test`, `channel::gap6`)

A valid trace round-trips (and round-trips through surrounding console noise). Every other case is a
deliberate attack that must come back as a bounded rejection — the test *returning at all* is the proof
of no panic/hang/OOM:

oversized raw (`TooLarge`) · a 4 MiB no-newline line (`TooLarge`, bounded) · too many lines · an
over-long line · no frame · BEGIN-without-END · bad base64 · `len` mismatch · `fnv` mismatch · invalid
JSON · **5000-deep nested JSON (no stack overflow → `BadJson`)** · no `edges` array · > 4096 records ·
confidence out of range · missing field · over-long name · **control-bytes in a name (accepted as
data, then sanitized for display)**.

## Live channel demo (`m2-channel.sh`) — measured on the real tier

```
[m2] ACCEPTED 2 observed edge(s) — bounded + validated, never eval'd:
[m2]   main -> gcd  (conf 90)
[m2]   gcd -> __imp_mod  (conf 80)        <- read off the REAL serial of a contained microVM, noise ignored
[m2] QUARANTINED — channel input rejected: declared fnv != decoded fnv (corruption/forgery)  <- corrupted channel
[m2] PASS positive ... [m2] PASS negative
```

So: a benign guest emitted a framed trace on serial, the host pulled it out of the kernel console
noise and accepted it; a corrupted copy was quarantined. The channel is real, one-way, and validated.

## What M2 does NOT do (next milestones)

- **No in-guest observer yet (M3).** The guest emitted a *canned* trace; producing a *real* one (a
  resolved IAT + observed indirect-call edges, via ptrace / QEMU-user trace) is M3.
- **No Scylla integration yet (M4).** `read_trace` returns `Vec<ObservedEdge>`; wiring those through
  `collaborate` (stamped `producer="dynamic"`, DD-007/DD-027) behind the engine port, on benign
  samples with `WRONG=0` held, is M4.
- **GAP-8 (evasion)** is inherent and remains for M5: a sample that detects the harness can emit a
  *valid but lying* trace. M2 guarantees it can't break the host; provenance/confidence (DD-007) must
  carry that the coverage was partial so the matcher never treats it as ground truth.

Reproduce: `KERNEL=<readable-bzImage> ./m2-channel.sh` (exit 0); `cargo test` in the spike dir (GAP-6).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
