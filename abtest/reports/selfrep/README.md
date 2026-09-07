# selfrep A/B reports

Historical test reports for the guarded multi-behavior `selfrep` fixture
(`abtest/corpus/src/selfrep.rs`); inert-by-default (`RUN_MODE=live` gate), **no live
self-replicator**. Each dated file set is a single 4-leg A/B run:

* NSA Ghidra 12.1.2 (stock, `ghidra_12.1.2_PUBLIC_20260605`) — raw `support/analyzeHeadless` + Scylla-wrapped (`scylla materialize` via the DD-034 sandbox, NSA dist mounted ro @ `/opt/ghidra`)
* GayHydra 26.3.0 — raw `analyzeHeadless` + Scylla-wrapped (same harness)

## Files per run

| name | contents |
|---|---|
| `<date>__4leg__*.tsv` | one row per binary (48); columns: arch/opt/panic/strip, `fns_<arm>`, `nsa_within_parity` (scilla-abtest `compare` inside-vs-outside), masked family, `nsa_B1B4`/`ghydra_B1B4`, cross-arm `xid`, note |
| `<date>__4leg__*.meta.json` | run header + headline aggregates (parity, B1-B4×48, masked family, verdict) |
| `<date>__4leg__*.md` | this dir — the rendered Markdown report for the run |

## Parity metric

`scylla-abtest compare --json <inside.scylla> <outside.snapshot.json>` (the canonical
inside-vs-outside structural parity check from `abtest/scripts/report.py`). A DIFF that also
appears in the raw-vs-raw control is engine nondeterminism (masked), not a wrapper fault.

## B1-B4 behavior signals (inferred by the RAW engine per binary)

| B1 enumerate | `readdir/opendir`+enumerate_files / `/proc/self` |
| B2 self-repl | `fs::copy`/`copy_file_range`/`copy_regular_files` + `replicate_self` + drop-target strings |
| B3 net-share | `mount`+`ptrace` imports + share paths (`cifs`/`nfs`/`9p`/`//missing/share`) |
| B4 anti-ana | `ptrace` + `DEBUGGER_PRESENT`/`STRACE`/`/proc/self` + `RUN_MODE` |

## Re-run

```
GHIDRA_DIST=/home/hermes/tmp/ghidra-dist/ghidra_12.1.2_PUBLIC   INSIDE_JOBS=2 bash ~/tmp/run_selfrep_4leg.sh   # then: python3 ~/tmp/gen_selfrep_report.py
```
