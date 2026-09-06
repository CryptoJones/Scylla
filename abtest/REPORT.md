# A/B parity report — inside Scylla vs raw engine headless

Run: 2026-09-06 13:58 on Ronin28 · engine dist: `ghidra_26.3.0_GayHydra-26.3.0` · scylla `4e45071` · 1356 binaries compared, 1354 at parity, control deterministic on 1327.

Inside = `scylla materialize` through the sandboxed engine-service (DD-034 container, gRPC over a Unix socket) → `.scylla`. Outside = the same dist's `support/analyzeHeadless` run directly on the host with the same `dump_model.java`. Control = the outside leg run again (engine determinism; a function the RAW engine reports two different ways across direct runs is engine nondeterminism, not a wrapper fault — such functions are *masked* from the field checks, listed by name, and recorded in `baselines/nondeterministic/`). CLI = `scylla functions/info --json` on the inside artifact vs on a `scylla-ingest` of the outside snapshot (byte-identical except the program name). Verdict rules: PARITY only when every function, every field, and the client-port projection agree.

## Summary by toolchain

| toolchain | binaries | at parity | functions compared | engine-deterministic on first control | engine-nondeterministic fns masked |
|---|---:|---:|---:|---:|---:|
| C (clang) | 252 | 252 | 3006 | 252 | 0 |
| C (gcc) | 784 | 784 | 10202 | 784 | 0 |
| C++ (clang++) | 56 | 56 | 1156 | 56 | 0 |
| C++ (g++) | 112 | 112 | 2746 | 112 | 0 |
| Go 1.22 | 48 | 48 | 91034 | 48 | 1 |
| Go 1.26 | 8 | 8 | 17748 | 8 | 0 |
| Rust | 96 | 94 | 63079 | 67 | 120 |
| **all** | **1356** | **1354** | **188971** | **1327** | **121** |

## Binaries needing a second look

Every row that is not a plain PARITY with byte-identical CLI output. The full per-binary table is in `REPORT-all.md`.

| binary | toolchain | fns inside | fns outside | inside vs outside | control | CLI JSON | notes |
|---|---|---:|---:|---|---|---|---|
| `gostr.go122.arm.O2.strip.elf` | Go 1.22 | 1188 | 1188 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_0007a454` — over 3 raw runs |
| `rustmath.rustc.x86-64.O0.abort.elf` | Rust | 645 | 645 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 4 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O0.abort.strip.elf` | Rust | 645 | 645 | **DIFFERS** (4 masked) | deterministic | **differs** | engine-nondeterministic, masked: `FUN_001363f0`, `FUN_00140f00`, `FUN_001416b0`, `FUN_00148ee0` — over 10 raw runs; 5 field, 0/0 only-in/only-out, 2 projection; CLI JSON differs |
| `rustmath.rustc.x86-64.O0.unwind.elf` | Rust | 651 | 651 | PARITY (4 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` — over 8 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O0.unwind.strip.elf` | Rust | 651 | 651 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00141a60` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O1.abort.elf` | Rust | 560 | 560 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 9 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O1.abort.strip.elf` | Rust | 559 | 559 | PARITY (4 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_0013f850`, `FUN_0013fc70`, `FUN_00140000`, `FUN_001476e0` — over 5 raw runs |
| `rustmath.rustc.x86-64.O1.unwind.elf` | Rust | 568 | 568 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 3 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | Rust | 568 | 568 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00135020`, `FUN_0013fd60`, `FUN_00140180`, `FUN_00140510` (+1) — over 6 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O2.abort.elf` | Rust | 560 | 560 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 4 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | Rust | 559 | 559 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134ca0`, `FUN_0013f7b0`, `FUN_0013fbd0`, `FUN_0013ff60` (+1) — over 3 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O2.unwind.elf` | Rust | 567 | 567 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 3 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O2.unwind.strip.elf` | Rust | 567 | 567 | PARITY (2 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134f80`, `FUN_001400e0` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O3.abort.elf` | Rust | 560 | 560 | PARITY (5 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 5 raw runs |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | Rust | 559 | 559 | PARITY (5 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134ca0`, `FUN_0013f7b0`, `FUN_0013fbd0`, `FUN_0013ff60` (+1) — over 7 raw runs |
| `rustmath.rustc.x86-64.O3.unwind.elf` | Rust | 567 | 567 | PARITY (4 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `fmt` — over 4 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.O3.unwind.strip.elf` | Rust | 567 | 567 | **DIFFERS** (2 masked) | **drifts** | **differs** | engine-nondeterministic, masked: `FUN_00134f90`, `FUN_001400f0` — over 10 raw runs; 15 field, 0/0 only-in/only-out, 6 projection; ENGINE NONDETERMINISTIC across two raw runs; CLI JSON differs |
| `rustmath.rustc.x86-64.Os.abort.elf` | Rust | 560 | 560 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 4 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | Rust | 559 | 559 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134b90`, `FUN_0013f6a0`, `FUN_0013fac0`, `FUN_0013fe50` (+1) — over 10 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.Os.unwind.elf` | Rust | 568 | 568 | PARITY (5 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 7 raw runs |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | Rust | 568 | 568 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134d70`, `FUN_0013fab0`, `FUN_0013fed0`, `FUN_00140260` (+1) — over 4 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.Oz.abort.strip.elf` | Rust | 563 | 563 | PARITY (2 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134b80`, `FUN_0013fab0` — over 5 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | Rust | 574 | 574 | PARITY (5 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 7 raw runs |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | Rust | 574 | 574 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134d30`, `FUN_0013fa70`, `FUN_0013fe90`, `FUN_00140220` (+1) — over 10 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O0.abort.elf` | Rust | 890 | 890 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 3 raw runs |
| `ruststr.rustc.x86-64.O0.abort.strip.elf` | Rust | 890 | 890 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00140a60` — over 5 raw runs |
| `ruststr.rustc.x86-64.O0.unwind.elf` | Rust | 910 | 910 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `rust_eh_personality` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O0.unwind.strip.elf` | Rust | 909 | 909 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00142660` — over 4 raw runs |
| `ruststr.rustc.x86-64.O1.abort.elf` | Rust | 575 | 575 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 4 raw runs |
| `ruststr.rustc.x86-64.O1.abort.strip.elf` | Rust | 574 | 574 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `FUN_00137c10` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O1.unwind.elf` | Rust | 597 | 597 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 6 raw runs |
| `ruststr.rustc.x86-64.O2.abort.elf` | Rust | 574 | 574 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 3 raw runs |
| `ruststr.rustc.x86-64.O2.abort.strip.elf` | Rust | 573 | 573 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `FUN_001379b0` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O2.unwind.elf` | Rust | 584 | 584 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `rust_eh_personality` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O2.unwind.strip.elf` | Rust | 584 | 584 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_001381e0` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O3.abort.elf` | Rust | 574 | 574 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `rust_eh_personality` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O3.abort.strip.elf` | Rust | 573 | 573 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00137a50` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.O3.unwind.elf` | Rust | 584 | 584 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 3 raw runs |
| `ruststr.rustc.x86-64.O3.unwind.strip.elf` | Rust | 584 | 584 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00138290` — over 4 raw runs |
| `ruststr.rustc.x86-64.Os.abort.elf` | Rust | 586 | 586 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.Os.abort.strip.elf` | Rust | 585 | 585 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `FUN_00137430` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.Os.unwind.elf` | Rust | 600 | 600 | PARITY (1 masked) | **drifts** | identical | engine-nondeterministic, masked: `rust_eh_personality` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.Os.unwind.strip.elf` | Rust | 600 | 600 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00137b80` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.Oz.abort.elf` | Rust | 610 | 610 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality` — over 4 raw runs |
| `ruststr.rustc.x86-64.Oz.abort.strip.elf` | Rust | 609 | 609 | PARITY (1 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00137200` — over 2 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `ruststr.rustc.x86-64.Oz.unwind.strip.elf` | Rust | 623 | 623 | PARITY (1 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00137850` — over 3 raw runs |

## Mismatch detail

### `rustmath.rustc.x86-64.O0.abort.strip.elf`

- `0x141320` `FUN_00141320` **size**: inside `787` · outside `810`
- `0x141320` `FUN_00141320` **bb_count**: inside `22` · outside `23`
- `0x141320` `FUN_00141320` **fingerprint**: inside `13340970737698715059` · outside `16030422130280618686`
- `0x141320` `FUN_00141320` **mnemonics**: inside `[("ADD", 4), ("AND", 5), ("CALL", 4), ("CMOVNS", 2), ("CMOVNZ", 5), ("CMOVS", 2), ("CMOVZ", 3), ("CMP", 5), ("JBE", 1), ` · outside `[("ADD", 5), ("AND", 5), ("CALL", 4), ("CMOVNS", 2), ("CMOVNZ", 5), ("CMOVS", 2), ("CMOVZ", 3), ("CMP", 5), ("JBE", 1), `
- `0x141320` `FUN_00141320` **trigrams**: inside `[("ADD JMP MOV", 1), ("ADD JZ MOV", 1), ("ADD POP POP", 1), ("ADD XOR JMP", 1), ("AND CMOVZ MOV", 1), ("AND LEA AND", 2)` · outside `[("ADD JMP MOV", 1), ("ADD JZ MOV", 1), ("ADD POP POP", 1), ("ADD XOR JMP", 1), ("ADD XOR MOV", 1), ("AND CMOVZ MOV", 1)`
- projection: `inside only: 0x141320	FUN_00141320	FUN_00141320 — 22 block(s), 4 out-call(s), 1 caller(s)	bb=Some(22)	size=Some(787)	callees=["FUN_001427c0", "FUN_00144a40", "F`
- projection: `outside only: 0x141320	FUN_00141320	FUN_00141320 — 23 block(s), 4 out-call(s), 1 caller(s)	bb=Some(23)	size=Some(810)	callees=["FUN_001427c0", "FUN_00144a40", "`

### `rustmath.rustc.x86-64.O3.unwind.strip.elf`

- `0x13fcd0` `FUN_0013fcd0` **size**: inside `1112` · outside `1056`
- `0x13fcd0` `FUN_0013fcd0` **bb_count**: inside `30` · outside `26`
- `0x13fcd0` `FUN_0013fcd0` **fingerprint**: inside `17859148475320543093` · outside `12156503105412347108`
- `0x13fcd0` `FUN_0013fcd0` **mnemonics**: inside `[("ADD", 9), ("AND", 5), ("CALL", 5), ("CMOVNC", 1), ("CMOVNS", 3), ("CMOVNZ", 5), ("CMOVS", 3), ("CMOVZ", 3), ("CMP", 1` · outside `[("ADD", 6), ("AND", 5), ("CALL", 5), ("CMOVNS", 3), ("CMOVNZ", 5), ("CMOVS", 3), ("CMOVZ", 3), ("CMP", 9), ("IMUL", 1),`
- `0x13fcd0` `FUN_0013fcd0` **trigrams**: inside `[("ADD ADD JZ", 1), ("ADD JZ MOV", 2), ("ADD MOV NEG", 1), ("ADD MOV SUB", 1), ("ADD MOVZX JMP", 1), ("ADD POP POP", 1),` · outside `[("ADD JZ MOV", 1), ("ADD MOV NEG", 1), ("ADD MOVZX JMP", 1), ("ADD POP POP", 1), ("ADD XOR JMP", 1), ("ADD XOR MOV", 1)`
- projection: `inside only: 0x13fcd0	FUN_0013fcd0	FUN_0013fcd0 — 30 block(s), 5 out-call(s), 1 caller(s)	bb=Some(30)	size=Some(1112)	callees=["FUN_0010b290", "FUN_00141590", "`
- projection: `inside only: 0x140480	FUN_00140480	FUN_00140480 — 33 block(s), 5 out-call(s), 3 caller(s)	bb=Some(33)	size=Some(586)	callees=["FUN_00140410", "FUN_00143980", "F`
- projection: `inside only: 0x147b60	FUN_00147b60	FUN_00147b60 — 81 block(s), 3 out-call(s), 0 caller(s)	bb=Some(81)	size=Some(1656)	callees=["FUN_0010b2e0", "FUN_00142d90", "`
- projection: `outside only: 0x13fcd0	FUN_0013fcd0	FUN_0013fcd0 — 26 block(s), 5 out-call(s), 1 caller(s)	bb=Some(26)	size=Some(1056)	callees=["FUN_0010b290", "FUN_00141590", `
- projection: `outside only: 0x140480	FUN_00140480	FUN_00140480 — 35 block(s), 5 out-call(s), 3 caller(s)	bb=Some(35)	size=Some(601)	callees=["FUN_00140410", "FUN_00143980", "`
- projection: `outside only: 0x147b60	FUN_00147b60	FUN_00147b60 — 87 block(s), 3 out-call(s), 0 caller(s)	bb=Some(87)	size=Some(1759)	callees=["FUN_0010b2e0", "FUN_00142d90", `


## Engine nondeterminism (masked functions)

The RAW engine, run directly several times on the same bytes, reported these functions with different body extents. That is a property of the engine's auto-analysis, observed with no Scylla in the loop, so they cannot be evidence for or against the wrapper and are excluded from the field checks above. Every other function in those binaries is at parity.

| binary | function | fields that vary | (size, blocks) variants seen | raw runs |
|---|---|---|---|---:|
| `gostr.go122.arm.O2.strip.elf` | `FUN_0007a454` @ 0x7a454 | bb_count | (136, 4), (136, 5) | 3 |
| `rustmath.rustc.x86-64.O0.abort.elf` | `rust_eh_personality` @ 0x1363f0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `rustmath.rustc.x86-64.O0.abort.elf` | `float_to_decimal_common_exact<f64>` @ 0x140f00 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 4 |
| `rustmath.rustc.x86-64.O0.abort.elf` | `float_to_decimal_common_shortest<f64>` @ 0x141320 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 4 |
| `rustmath.rustc.x86-64.O0.abort.elf` | `escape_debug_ext` @ 0x1416b0 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 4 |
| `rustmath.rustc.x86-64.O0.abort.elf` | `fmt` @ 0x148ee0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 4 |
| `rustmath.rustc.x86-64.O0.abort.strip.elf` | `FUN_001363f0` @ 0x1363f0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 10 |
| `rustmath.rustc.x86-64.O0.abort.strip.elf` | `FUN_00140f00` @ 0x140f00 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32), (1112, 34) | 10 |
| `rustmath.rustc.x86-64.O0.abort.strip.elf` | `FUN_001416b0` @ 0x1416b0 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 10 |
| `rustmath.rustc.x86-64.O0.abort.strip.elf` | `FUN_00148ee0` @ 0x148ee0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 10 |
| `rustmath.rustc.x86-64.O0.unwind.elf` | `rust_eh_personality` @ 0x1370c0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 8 |
| `rustmath.rustc.x86-64.O0.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x141e00 | size, bb_count, mnemonics, trigrams | (1056, 26), (1069, 28) | 8 |
| `rustmath.rustc.x86-64.O0.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x142220 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 8 |
| `rustmath.rustc.x86-64.O0.unwind.elf` | `escape_debug_ext` @ 0x1425b0 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 8 |
| `rustmath.rustc.x86-64.O0.unwind.strip.elf` | `FUN_00141a60` @ 0x141a60 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 2 |
| `rustmath.rustc.x86-64.O1.abort.elf` | `rust_eh_personality` @ 0x134d40 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 9 |
| `rustmath.rustc.x86-64.O1.abort.elf` | `float_to_decimal_common_exact<f64>` @ 0x13f850 | size, bb_count, mnemonics, trigrams | (1056, 26), (1069, 28), (1099, 28) | 9 |
| `rustmath.rustc.x86-64.O1.abort.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fc70 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 9 |
| `rustmath.rustc.x86-64.O1.abort.elf` | `escape_debug_ext` @ 0x140000 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 9 |
| `rustmath.rustc.x86-64.O1.abort.elf` | `fmt` @ 0x1476e0 | size, bb_count, mnemonics, trigrams | (1656, 81), (1759, 87) | 9 |
| `rustmath.rustc.x86-64.O1.abort.strip.elf` | `FUN_0013f850` @ 0x13f850 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 5 |
| `rustmath.rustc.x86-64.O1.abort.strip.elf` | `FUN_0013fc70` @ 0x13fc70 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 5 |
| `rustmath.rustc.x86-64.O1.abort.strip.elf` | `FUN_00140000` @ 0x140000 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 5 |
| `rustmath.rustc.x86-64.O1.abort.strip.elf` | `FUN_001476e0` @ 0x1476e0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 5 |
| `rustmath.rustc.x86-64.O1.unwind.elf` | `rust_eh_personality` @ 0x135020 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `rustmath.rustc.x86-64.O1.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fd60 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 3 |
| `rustmath.rustc.x86-64.O1.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x140180 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 3 |
| `rustmath.rustc.x86-64.O1.unwind.elf` | `escape_debug_ext` @ 0x140510 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 3 |
| `rustmath.rustc.x86-64.O1.unwind.elf` | `fmt` @ 0x147bf0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 3 |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | `FUN_00135020` @ 0x135020 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 6 |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | `FUN_0013fd60` @ 0x13fd60 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32) | 6 |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | `FUN_00140180` @ 0x140180 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23), (823, 25) | 6 |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | `FUN_00140510` @ 0x140510 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 6 |
| `rustmath.rustc.x86-64.O1.unwind.strip.elf` | `FUN_00147bf0` @ 0x147bf0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 6 |
| `rustmath.rustc.x86-64.O2.abort.elf` | `rust_eh_personality` @ 0x134ca0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `rustmath.rustc.x86-64.O2.abort.elf` | `float_to_decimal_common_exact<f64>` @ 0x13f7b0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1069, 28), (1099, 32) | 4 |
| `rustmath.rustc.x86-64.O2.abort.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fbd0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 4 |
| `rustmath.rustc.x86-64.O2.abort.elf` | `escape_debug_ext` @ 0x13ff60 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 4 |
| `rustmath.rustc.x86-64.O2.abort.elf` | `fmt` @ 0x147640 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 4 |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | `FUN_00134ca0` @ 0x134ca0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | `FUN_0013f7b0` @ 0x13f7b0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1069, 28), (1099, 32) | 3 |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | `FUN_0013fbd0` @ 0x13fbd0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 3 |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | `FUN_0013ff60` @ 0x13ff60 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 3 |
| `rustmath.rustc.x86-64.O2.abort.strip.elf` | `FUN_00147640` @ 0x147640 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.elf` | `rust_eh_personality` @ 0x134f80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fcc0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 30) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x1400e0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.elf` | `escape_debug_ext` @ 0x140470 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.elf` | `fmt` @ 0x147b50 | size, bb_count, mnemonics, trigrams | (1656, 81), (1759, 87) | 3 |
| `rustmath.rustc.x86-64.O2.unwind.strip.elf` | `FUN_00134f80` @ 0x134f80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `rustmath.rustc.x86-64.O2.unwind.strip.elf` | `FUN_001400e0` @ 0x1400e0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 2 |
| `rustmath.rustc.x86-64.O3.abort.elf` | `rust_eh_personality` @ 0x134ca0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 5 |
| `rustmath.rustc.x86-64.O3.abort.elf` | `float_to_decimal_common_exact<f64>` @ 0x13f7b0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 5 |
| `rustmath.rustc.x86-64.O3.abort.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fbd0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 5 |
| `rustmath.rustc.x86-64.O3.abort.elf` | `escape_debug_ext` @ 0x13ff60 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 5 |
| `rustmath.rustc.x86-64.O3.abort.elf` | `fmt` @ 0x147640 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 5 |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | `FUN_00134ca0` @ 0x134ca0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 7 |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | `FUN_0013f7b0` @ 0x13f7b0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 7 |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | `FUN_0013fbd0` @ 0x13fbd0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 7 |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | `FUN_0013ff60` @ 0x13ff60 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 7 |
| `rustmath.rustc.x86-64.O3.abort.strip.elf` | `FUN_00147640` @ 0x147640 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 7 |
| `rustmath.rustc.x86-64.O3.unwind.elf` | `rust_eh_personality` @ 0x134f90 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `rustmath.rustc.x86-64.O3.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fcd0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32) | 4 |
| `rustmath.rustc.x86-64.O3.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x1400f0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 4 |
| `rustmath.rustc.x86-64.O3.unwind.elf` | `fmt` @ 0x147b60 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 4 |
| `rustmath.rustc.x86-64.O3.unwind.strip.elf` | `FUN_00134f90` @ 0x134f90 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 10 |
| `rustmath.rustc.x86-64.O3.unwind.strip.elf` | `FUN_001400f0` @ 0x1400f0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 10 |
| `rustmath.rustc.x86-64.Os.abort.elf` | `rust_eh_personality` @ 0x134b90 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `rustmath.rustc.x86-64.Os.abort.elf` | `float_to_decimal_common_exact<f64>` @ 0x13f6a0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 4 |
| `rustmath.rustc.x86-64.Os.abort.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fac0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 4 |
| `rustmath.rustc.x86-64.Os.abort.elf` | `escape_debug_ext` @ 0x13fe50 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 4 |
| `rustmath.rustc.x86-64.Os.abort.elf` | `fmt` @ 0x147530 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 4 |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | `FUN_00134b90` @ 0x134b90 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 10 |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | `FUN_0013f6a0` @ 0x13f6a0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 10 |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | `FUN_0013fac0` @ 0x13fac0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 10 |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | `FUN_0013fe50` @ 0x13fe50 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 10 |
| `rustmath.rustc.x86-64.Os.abort.strip.elf` | `FUN_00147530` @ 0x147530 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 10 |
| `rustmath.rustc.x86-64.Os.unwind.elf` | `rust_eh_personality` @ 0x134d70 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 7 |
| `rustmath.rustc.x86-64.Os.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fab0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 28), (1099, 32) | 7 |
| `rustmath.rustc.x86-64.Os.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fed0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 7 |
| `rustmath.rustc.x86-64.Os.unwind.elf` | `escape_debug_ext` @ 0x140260 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 7 |
| `rustmath.rustc.x86-64.Os.unwind.elf` | `fmt` @ 0x147940 | size, bb_count, mnemonics, trigrams | (1656, 81), (1701, 82), (1759, 87) | 7 |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | `FUN_00134d70` @ 0x134d70 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | `FUN_0013fab0` @ 0x13fab0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32) | 4 |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | `FUN_0013fed0` @ 0x13fed0 | size, bb_count, mnemonics, trigrams | (810, 23), (823, 25) | 4 |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | `FUN_00140260` @ 0x140260 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 4 |
| `rustmath.rustc.x86-64.Os.unwind.strip.elf` | `FUN_00147940` @ 0x147940 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 4 |
| `rustmath.rustc.x86-64.Oz.abort.strip.elf` | `FUN_00134b80` @ 0x134b80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 5 |
| `rustmath.rustc.x86-64.Oz.abort.strip.elf` | `FUN_0013fab0` @ 0x13fab0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 5 |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | `rust_eh_personality` @ 0x134d30 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 7 |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fa70 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32), (1112, 34) | 7 |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | `float_to_decimal_common_shortest<f64>` @ 0x13fe90 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 7 |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | `escape_debug_ext` @ 0x140220 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 7 |
| `rustmath.rustc.x86-64.Oz.unwind.elf` | `fmt` @ 0x147900 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 7 |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_00134d30` @ 0x134d30 | size, bb_count, mnemonics, trigrams | (1168, 83), (1222, 88), (1318, 89), (1370, 90) | 10 |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_0013fa70` @ 0x13fa70 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 32), (1112, 34) | 10 |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_0013fe90` @ 0x13fe90 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 10 |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_00140220` @ 0x140220 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 10 |
| `rustmath.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_00147900` @ 0x147900 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 10 |
| `ruststr.rustc.x86-64.O0.abort.elf` | `rust_eh_personality` @ 0x140a60 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `ruststr.rustc.x86-64.O0.abort.strip.elf` | `FUN_00140a60` @ 0x140a60 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 5 |
| `ruststr.rustc.x86-64.O0.unwind.elf` | `rust_eh_personality` @ 0x145c20 | size, bb_count, mnemonics, trigrams | (1308, 89), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O0.unwind.strip.elf` | `FUN_00142660` @ 0x142660 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `ruststr.rustc.x86-64.O1.abort.elf` | `rust_eh_personality` @ 0x137c10 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `ruststr.rustc.x86-64.O1.abort.strip.elf` | `FUN_00137c10` @ 0x137c10 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O1.unwind.elf` | `rust_eh_personality` @ 0x138950 | size, bb_count, mnemonics, trigrams | (1308, 89), (1370, 90) | 6 |
| `ruststr.rustc.x86-64.O2.abort.elf` | `rust_eh_personality` @ 0x1379b0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `ruststr.rustc.x86-64.O2.abort.strip.elf` | `FUN_001379b0` @ 0x1379b0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O2.unwind.elf` | `rust_eh_personality` @ 0x1381b0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O2.unwind.strip.elf` | `FUN_001381e0` @ 0x1381e0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O3.abort.elf` | `rust_eh_personality` @ 0x137a50 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O3.abort.strip.elf` | `FUN_00137a50` @ 0x137a50 | size, bb_count, mnemonics, trigrams | (1318, 89), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.O3.unwind.elf` | `rust_eh_personality` @ 0x138290 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |
| `ruststr.rustc.x86-64.O3.unwind.strip.elf` | `FUN_00138290` @ 0x138290 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `ruststr.rustc.x86-64.Os.abort.elf` | `rust_eh_personality` @ 0x137430 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.Os.abort.strip.elf` | `FUN_00137430` @ 0x137430 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.Os.unwind.elf` | `rust_eh_personality` @ 0x137b80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.Os.unwind.strip.elf` | `FUN_00137b80` @ 0x137b80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.Oz.abort.elf` | `rust_eh_personality` @ 0x137200 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 4 |
| `ruststr.rustc.x86-64.Oz.abort.strip.elf` | `FUN_00137200` @ 0x137200 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 2 |
| `ruststr.rustc.x86-64.Oz.unwind.strip.elf` | `FUN_00137850` @ 0x137850 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 3 |

## Run notes

- `gomath.go126.amd64.O0.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gomath.go126.amd64.O0.strip.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gomath.go126.amd64.O2.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gomath.go126.amd64.O2.strip.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gostr.go126.amd64.O0.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gostr.go126.amd64.O0.strip.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gostr.go126.amd64.O2.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.
- `gostr.go126.amd64.O2.strip.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.

Re-run: `GHIDRA_DIST=<dist> abtest/scripts/ab.sh` (see `abtest/README.md`).
