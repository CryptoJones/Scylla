# A/B parity report — inside Scylla vs raw engine headless

Run: 2026-09-06 01:20 on Ronin28 · engine dist: `ghidra_26.3.0_GayHydra-26.3.0` · scylla `62dea9b` · 22 binaries compared, 22 at parity, control deterministic on 20.

Inside = `scylla materialize` through the sandboxed engine-service (DD-034 container, gRPC over a Unix socket) → `.scylla`. Outside = the same dist's `support/analyzeHeadless` run directly on the host with the same `dump_model.java`. Control = the outside leg run again (engine determinism; a function the RAW engine reports two different ways across direct runs is engine nondeterminism, not a wrapper fault — such functions are *masked* from the field checks, listed by name, and recorded in `baselines/nondeterministic/`). CLI = `scylla functions/info --json` on the inside artifact vs on a `scylla-ingest` of the outside snapshot (byte-identical except the program name). Verdict rules: PARITY only when every function, every field, and the client-port projection agree.

| binary | toolchain | fns inside | fns outside | inside vs outside | control | CLI JSON | notes |
|---|---|---:|---:|---|---|---|---|
| `gomath.go122.amd64.O0.elf` | Go 1.22 | 2410 | 2410 | PARITY | deterministic | identical |  |
| `gomath.go122.amd64.O2.elf` | Go 1.22 | 1576 | 1576 | PARITY | deterministic | identical |  |
| `gomath.go122.amd64.O2.strip.elf` | Go 1.22 | 1575 | 1575 | PARITY | deterministic | identical |  |
| `gomath.go126.amd64.O2.elf` | Go 1.26 | 1943 | 1943 | PARITY | deterministic | identical |  |
| `mathlib.c.i386.O0.elf` | C | 16 | 16 | PARITY | deterministic | identical |  |
| `mathlib.c.i386.O2.elf` | C | 12 | 12 | PARITY | deterministic | identical |  |
| `mathlib.c.i386.O2.strip.elf` | C | 12 | 12 | PARITY | deterministic | identical |  |
| `mathlib.c.x86-64.O0.elf` | C | 13 | 13 | PARITY | deterministic | identical |  |
| `mathlib.c.x86-64.O2.elf` | C | 10 | 10 | PARITY | deterministic | identical |  |
| `mathlib.c.x86-64.O2.strip.elf` | C | 10 | 10 | PARITY | deterministic | identical |  |
| `rustmath.rs.x86-64.O0.elf` | Rust | 651 | 651 | PARITY (5 masked) | deterministic | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 6 raw runs |
| `rustmath.rs.x86-64.O2.elf` | Rust | 567 | 567 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `rust_eh_personality`, `float_to_decimal_common_exact<f64>`, `float_to_decimal_common_shortest<f64>`, `escape_debug_ext` (+1) — over 6 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `rustmath.rs.x86-64.O2.strip.elf` | Rust | 567 | 567 | PARITY (5 masked) | **drifts** | identical (masked fns aside) | engine-nondeterministic, masked: `FUN_00134f80`, `FUN_0013fcc0`, `FUN_001400e0`, `FUN_00140470` (+1) — over 12 raw runs; ENGINE NONDETERMINISTIC across two raw runs |
| `shapes.cpp.x86-64.O0.elf` | C++ | 21 | 21 | PARITY | deterministic | identical |  |
| `shapes.cpp.x86-64.O2.elf` | C++ | 15 | 15 | PARITY | deterministic | identical |  |
| `shapes.cpp.x86-64.O2.strip.elf` | C++ | 15 | 15 | PARITY | deterministic | identical |  |
| `strutil.c.i386.O0.elf` | C | 16 | 16 | PARITY | deterministic | identical |  |
| `strutil.c.i386.O2.elf` | C | 13 | 13 | PARITY | deterministic | identical |  |
| `strutil.c.i386.O2.strip.elf` | C | 13 | 13 | PARITY | deterministic | identical |  |
| `strutil.c.x86-64.O0.elf` | C | 12 | 12 | PARITY | deterministic | identical |  |
| `strutil.c.x86-64.O2.elf` | C | 9 | 9 | PARITY | deterministic | identical |  |
| `strutil.c.x86-64.O2.strip.elf` | C | 9 | 9 | PARITY | deterministic | identical |  |

## Engine nondeterminism (masked functions)

The RAW engine, run directly several times on the same bytes, reported these functions with different body extents. That is a property of the engine's auto-analysis, observed with no Scylla in the loop, so they cannot be evidence for or against the wrapper and are excluded from the field checks above. Every other function in those binaries is at parity.

| binary | function | fields that vary | (size, blocks) variants seen | raw runs |
|---|---|---|---|---:|
| `rustmath.rs.x86-64.O0.elf` | `rust_eh_personality` @ 0x1370c0 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 6 |
| `rustmath.rs.x86-64.O0.elf` | `float_to_decimal_common_exact<f64>` @ 0x141e00 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 6 |
| `rustmath.rs.x86-64.O0.elf` | `float_to_decimal_common_shortest<f64>` @ 0x142220 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 6 |
| `rustmath.rs.x86-64.O0.elf` | `escape_debug_ext` @ 0x1425b0 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 6 |
| `rustmath.rs.x86-64.O0.elf` | `fmt` @ 0x149de0 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 6 |
| `rustmath.rs.x86-64.O2.elf` | `rust_eh_personality` @ 0x134f80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 6 |
| `rustmath.rs.x86-64.O2.elf` | `float_to_decimal_common_exact<f64>` @ 0x13fcc0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1112, 34) | 6 |
| `rustmath.rs.x86-64.O2.elf` | `float_to_decimal_common_shortest<f64>` @ 0x1400e0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 6 |
| `rustmath.rs.x86-64.O2.elf` | `escape_debug_ext` @ 0x140470 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 6 |
| `rustmath.rs.x86-64.O2.elf` | `fmt` @ 0x147b50 | size, bb_count, mnemonics, trigrams | (1701, 82), (1759, 87) | 6 |
| `rustmath.rs.x86-64.O2.strip.elf` | `FUN_00134f80` @ 0x134f80 | size, bb_count, mnemonics, trigrams | (1168, 83), (1370, 90) | 12 |
| `rustmath.rs.x86-64.O2.strip.elf` | `FUN_0013fcc0` @ 0x13fcc0 | size, bb_count, mnemonics, trigrams | (1056, 26), (1099, 28), (1099, 32) | 12 |
| `rustmath.rs.x86-64.O2.strip.elf` | `FUN_001400e0` @ 0x1400e0 | size, bb_count, mnemonics, trigrams | (787, 22), (810, 23) | 12 |
| `rustmath.rs.x86-64.O2.strip.elf` | `FUN_00140470` @ 0x140470 | size, bb_count, mnemonics, trigrams | (586, 33), (601, 35) | 12 |
| `rustmath.rs.x86-64.O2.strip.elf` | `FUN_00147b50` @ 0x147b50 | size, bb_count, mnemonics, trigrams | (1656, 81), (1701, 82), (1759, 87) | 12 |

## Run notes

- `gomath.go126.amd64.O2.elf`: the engine's GolangSymbolAnalyzer failed on this binary (`INFO  Go version 1.26.0 (GolangSymbolAnalyzer)` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.

Re-run: `GHIDRA_DIST=<dist> abtest/scripts/ab.sh` (see `abtest/README.md`).
