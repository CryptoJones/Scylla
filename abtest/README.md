# A/B parity harness — inside Scylla vs the raw engine

**The question:** when Scylla materializes a binary, is what it reports *exactly* what the engine
reports when you run the engine yourself? Scylla wraps GayHydra behind a sandbox, a gRPC stream, a
Rust assembler and a Cap'n Proto artifact — four places a function, an edge, or a count could go
missing or drift. This harness proves they don't, for C, C++, Go and Rust binaries, and records both
legs in the repo so the same test can be re-run against any future Scylla or engine build.

## The two legs

Same engine dist on both sides — `GHIDRA_DIST` points at one unpacked GayHydra — so any delta is
attributable to the wrapper, never to the engine:

| leg | what runs | output |
|-----|-----------|--------|
| **inside** (A) | `scylla materialize unix:… <bin> out.scylla` → `engine-service/run-sandboxed.sh` (DD-034 container: no network, RO rootfs, caps dropped) → cold `analyzeHeadless` + `dump_model.java` → gRPC `Materialize` stream → `scylla_engine::assemble` → `.scylla` | `baselines/inside/<bin>.scylla.gz` |
| **outside** (B) | the dist's `support/analyzeHeadless` run *directly on the host* with the *same* `engine-service/scripts/dump_model.java` post-script — the command line `EngineServer.java` uses, minus Scylla | `baselines/outside/<bin>.snapshot.json.gz` |
| **control** | the outside leg run again (`CONTROL_RUNS`, default 2) | engine determinism: separates "the engine drifts" from "the wrapper is wrong" — see below |
| **decomp** | outside only: `scripts/DumpDecomp.java` — decompiled C, prototype, calling convention, disassembly + raw P-code per function, sorted by entry | `baselines/decomp/<bin>.decomp.txt` |

Scylla's model carries **no decompiled C yet** (the engine-service `Decompile` RPC is unimplemented),
so the decomp leg is recorded, not compared: it is the committed baseline the `decompile` verb will
be A/B-tested against the day it lands. For Go and Rust it is filtered to user code (`main.`,
`rustmath`) so the committed text stays small; C/C++ dump every function.

## What "parity" means

`crates/scylla-abtest` reduces both legs to one canonical form — keyed by **entry address**, never by
stable id (ids are minted per materialization) and never by program **name** (Scylla imports the bytes
under a temp filename; the raw run under the real one — the one field that legitimately differs) —
and compares, per function: name, size, basic-block count, callee addresses, mnemonic fingerprint,
mnemonic histogram, ordered trigrams, string refs, imports, package-qualified callee names, BSim
vector; plus the SLEIGH language id and the function set itself. Then it projects both through the
client port's `functions(Detail)` and compares what a head would actually display. `ab.sh` adds a
CLI-level byte check: `scylla functions --json` / `info --json` on the inside artifact vs on a
`scylla-ingest` of the outside snapshot must be byte-identical (program name aside).

**PARITY** is declared only when *nothing* differs. The report never hides a mismatch.

### Engine nondeterminism is measured, then masked by evidence, never by hand

The raw engine is not perfectly deterministic: on the Rust corpus, two std functions
(`rust_eh_personality`, `float_to_decimal_common_shortest<f64>`) come back with one of two body
extents from one direct `analyzeHeadless` run to the next — with no Scylla anywhere in the loop.
A function the engine itself reports two ways cannot be evidence for or against the wrapper, so:

1. `ab.sh` runs the raw leg several times (`outside` + `CONTROL_RUNS` controls) and
   `scylla-abtest flaky` lists, per binary, every function any raw run disagrees on — address,
   names, the fields that vary, every `(size, blocks)` variant seen, and how many runs. Engine-only
   evidence.
2. `scylla-abtest compare --ignore <flaky.json>` excludes exactly those functions from the per-field
   and projection checks, **lists them in the verdict** (`PARITY (2 engine-nondeterministic
   function(s) masked)`), and still counts them toward the function set — a masked function missing
   from one leg is a real difference.
3. The record is committed beside the pair as `baselines/nondeterministic/<bin>.json` so the
   offline gate masks the same functions for the same reason, and the report prints the table.

There is no hand-written allowlist anywhere. If a new mismatch appears that the raw runs do not
also show, it is a wrapper bug and the run says **DIFFERS**.

## Re-running

```sh
# prerequisites: docker + scylla-engine-service:dev (engine-service/README.md), JDK 21 on PATH,
# gcc/g++ (+ gcc-multilib for i386), go (with the go1.22.0 toolchain cached), rustc, python3
GHIDRA_DIST=/abs/path/to/ghidra_26.3.0_GayHydra-26.3.0 abtest/scripts/ab.sh
```

That builds the corpus + tools, runs outside → control → inside sequentially (each headless run is
a full JVM; ~30–45 min for the 22-binary corpus), compares, writes `abtest/REPORT.md`, and refreshes
`abtest/baselines/`. `STAGES=inside,compare,report` re-runs a subset into the same run dir
(`abtest/out/<stamp>/`, git-ignored); `NO_BASELINES=1` is a dry run. One pair by hand:

```sh
target/debug/scylla-abtest compare abtest/baselines/inside/mathlib.c.x86-64.O0.elf.scylla.gz \
                                   abtest/baselines/outside/mathlib.c.x86-64.O0.elf.snapshot.json.gz
# exit 0 = PARITY, 1 = differs (names the addr + field), 2 = trouble — `scylla diff` semantics.
# The committed legs are gzipped (a Go .scylla is ~4 MB raw); the tools read .gz in place, and
# `gunzip -c … > x.scylla` hands one to the ordinary `scylla` CLI.
```

**The offline gate.** `crates/scylla-abtest/tests/parity.rs` replays every committed baseline pair on
every `cargo test --workspace` — no engine, no docker — so a change to the ingest / assemble / loader
path that made Scylla's model drift from the engine's own output fails CI. Re-record with `ab.sh`
when the engine dist or the snapshot schema changes on purpose.

## The corpus (`corpus/`)

Same small programs, four toolchains, two optimization levels, stripped variants (the stripped
builds prove the wrapper is faithful when the engine has *no* names to lean on):

| toolchain | source | builds |
|-----------|--------|--------|
| C (gcc)   | `prototype/corpus/src/mathlib.c`, `strutil.c` | x86-64 + i386 × O0/O2, stripped O2 |
| C++ (g++) | `prototype/corpus/src/shapes.cpp` (vtables, mangling) | x86-64 O0/O2, stripped O2 |
| Go        | `prototype/corpus/src/gomath.go` | go1.22.0 amd64 O0 (`-N -l`) / O2 / stripped (`-s -w`); one go1.26 O2 (see report) |
| Rust      | `corpus/src/rustmath.rs` (mathlib's call graph + a trait object) | x86-64 opt-level 0/2, stripped 2 |

`corpus/build.sh` regenerates `corpus/bin/` (deterministic where the toolchain allows: fixed
`SOURCE_DATE_EPOCH`, no build-id, trimmed paths). The C/C++/Go sources are reused from
`prototype/corpus/src` — one source of truth; the Rust sample is the only new source.

## Reading `REPORT.md`

One row per binary: function counts on each leg, the inside-vs-outside verdict, whether the control
run was deterministic, whether the CLI JSON was byte-identical, and notes. A **DIFFERS** row gets a
detail section naming the address, the function and the field on each side. Read the control column
first: a row whose masked count is non-zero had engine nondeterminism measured out of it (the
"Engine nondeterminism" table says which functions and what the engine did); a row that says
**DIFFERS** is a wrapper bug — fix it, never widen the comparator to hide it.
