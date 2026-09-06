#!/usr/bin/env bash
# The A/B parity run, end to end:
#   corpus build -> OUTSIDE leg (+ a CONTROL repeat) -> INSIDE leg -> DECOMP leg -> compare -> REPORT.md -> baselines
#
#   GHIDRA_DIST=/path/to/ghidra_26.3.0_GayHydra-26.3.0 abtest/scripts/ab.sh [run-dir]
#
# STAGES=build,outside,control,inside,decomp,compare,report,baselines (default all) selects stages,
# so a failed leg can be re-run alone into the same run-dir. The `decomp` stage is the DECOMPILATION
# leg: `scylla decompile --json` through the sandbox for every binary (the engine-service `Decompile`
# RPC), compared byte-for-byte per function against the raw engine's own DumpDecomp.java dump from
# the outside leg (`scylla-abtest decomp`). CONTROL_RUNS=N (default 1) repeats the raw
# outside leg N times into control, control2, ...: the ENGINE's own run-to-run nondeterminism is
# characterized from those raw runs alone (`scylla-abtest flaky`) and the functions it flips are
# masked — and listed — in the inside-vs-outside verdict, so an engine wobble is never mistaken for
# a wrapper fault and a wrapper fault is never hidden behind one. RETRY_CONTROLS=N (default 8): when
# a pair DIFFERS, gather more ENGINE evidence first — up to N extra raw runs of THAT binary — and
# re-judge; only what the raw engine is seen to flip is ever masked. JOBS=N (default 3) runs the raw
# legs N binaries at a time; INSIDE_JOBS=N (default 2) materializes N at a time through the sandbox.
# NO_BASELINES=1 leaves abtest/baselines/ untouched (a dry run); otherwise the baselines are
# REPLACED by this run's pairs (a full run defines the committed set). Requires: the engine dist, docker + scylla-engine-service:dev, JDK 21,
# the Rust workspace (built here), python3. Runs the legs SEQUENTIALLY — each headless run is a
# full JVM, and running both legs at once would contend for the host and blur timings.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${ABTEST_REPO:-$(cd "$HERE/../.." && pwd)}"
: "${GHIDRA_DIST:?set GHIDRA_DIST to the unpacked engine dist}"
RUN="${1:-$REPO/abtest/out/$(date +%Y%m%d-%H%M%S)}"
# A run takes hours. Execute from a SNAPSHOT of the scripts so editing abtest/scripts/ mid-run can
# never corrupt the running instance (bash reads a script incrementally) or change its behaviour.
if [ -z "${ABTEST_SNAPPED:-}" ]; then
  mkdir -p "$RUN/scripts"; cp "$HERE"/*.sh "$HERE"/*.py "$HERE"/*.java "$RUN/scripts/"
  exec env ABTEST_SNAPPED=1 ABTEST_REPO="$REPO" bash "$RUN/scripts/ab.sh" "$RUN"
fi
STAGES="${STAGES:-build,outside,control,inside,decomp,compare,report,baselines}"
has() { [[ ",$STAGES," == *",$1,"* ]]; }
mkdir -p "$RUN"
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}" CXX="${CXX:-/usr/bin/g++}"
SCYLLA="$REPO/target/debug/scylla"; ABTEST="$REPO/target/debug/scylla-abtest"; INGEST="$REPO/target/debug/scylla-ingest"
export SCYLLA
log() { echo "[$(date +%H:%M:%S)] $*"; }

if has build; then
  log "build: corpus + rust tools"
  "$REPO/abtest/corpus/build.sh" | tail -1
  (cd "$REPO" && cargo build -q -p scylla-cli -p scylla-abtest -p scylla-ingest)
fi
if has outside; then
  log "outside leg -> $RUN/outside (JOBS=${JOBS:-3})"
  JOBS="${JOBS:-3}" "$HERE/run-outside.sh" "$RUN/outside" || log "outside: some binaries FAILED (continuing)"
fi
if has control; then
  for i in $(seq 1 "${CONTROL_RUNS:-1}"); do
    d="$RUN/control"; [ "$i" -gt 1 ] && d="$RUN/control$i"
    log "control leg $i/${CONTROL_RUNS:-1} (outside repeated, snapshot only) -> $d (JOBS=${JOBS:-3})"
    JOBS="${JOBS:-3}" NO_DECOMP=1 "$HERE/run-outside.sh" "$d" || log "control $i: some binaries FAILED (continuing)"
  done
fi
if has inside; then
  log "inside leg -> $RUN/inside (INSIDE_JOBS=${INSIDE_JOBS:-1})"
  INSIDE_JOBS="${INSIDE_JOBS:-1}" "$HERE/run-inside.sh" "$RUN/inside" || log "inside: some binaries FAILED (continuing)"
fi
if has decomp; then
  log "decomp leg (scylla decompile through the sandbox) -> $RUN/decomp-inside (INSIDE_JOBS=${INSIDE_JOBS:-1})"
  LEG=decomp INSIDE_JOBS="${INSIDE_JOBS:-1}" "$HERE/run-inside.sh" "$RUN/decomp-inside" || log "decomp: some binaries FAILED (continuing)"
fi
if has compare; then
  log "compare"
  mkdir -p "$RUN/compare" "$RUN/cli" "$RUN/tmp" "$RUN/flaky" "$RUN/decomp-compare"
  for snap in "$RUN"/outside/*.elf.snapshot.json; do
    name="$(basename "$snap" .snapshot.json)"
    art="$RUN/inside/$name.scylla"
    [ -s "$art" ] || { log "  $name: no inside artifact — skipped"; continue; }
    # ENGINE nondeterminism: every raw run of this binary (outside + all controls), engine-only evidence
    judge() {
      raw=("$snap"); for c in "$RUN"/control*/"$name.snapshot.json"; do [ -s "$c" ] && raw+=("$c"); done
      ignore=()
      if [ "${#raw[@]}" -ge 2 ]; then
        "$ABTEST" flaky "$RUN/flaky/$name.json" "${raw[@]}" >/dev/null
        ignore=(--ignore "$RUN/flaky/$name.json")
      fi
      set +e
      "$ABTEST" compare --json "${ignore[@]}" "$art" "$snap" >"$RUN/compare/$name.json"; rc=$?
      set -e
    }
    judge
    # A mismatch is NOT accepted at face value: gather more raw-engine evidence for this one binary
    # (one extra direct run at a time, re-judging after each) before concluding anything. If the
    # engine is seen to flip the mismatching functions, they are masked as engine nondeterminism; if
    # it never does, the verdict stays DIFFERS — a wrapper fault.
    k=0
    while [ $rc -eq 1 ] && [ $k -lt "${RETRY_CONTROLS:-8}" ]; do
      k=$((k+1))
      log "  $name: DIFFERS after ${#raw[@]} raw runs — gathering engine evidence (extra raw run $k)"
      NO_DECOMP=1 "$HERE/run-outside.sh" "$RUN/control-extra$k" "$REPO/abtest/corpus/bin/$name" >/dev/null || true
      judge
    done
    # control: outside vs outside-repeat, UNMASKED, via ingest (same tool, same canonical form)
    if [ -s "$RUN/control/$name.snapshot.json" ]; then
      "$INGEST" "$RUN/control/$name.snapshot.json" "$RUN/tmp/$name.control.scylla" 2>/dev/null
      "$ABTEST" compare --json "$RUN/tmp/$name.control.scylla" "$snap" >"$RUN/control/$name.json" || true
    fi
    # CLI-level byte check: what the terminal head prints, inside vs an ingest of the outside snapshot
    "$INGEST" "$snap" "$RUN/tmp/$name.outside.scylla" 2>/dev/null
    { "$SCYLLA" functions --json "$art" detail; "$SCYLLA" info --json "$art" | python3 -c 'import json,sys;d=json.load(sys.stdin);d.pop("name");print(json.dumps(d))'; } >"$RUN/tmp/$name.cli.inside"
    { "$SCYLLA" functions --json "$RUN/tmp/$name.outside.scylla" detail; "$SCYLLA" info --json "$RUN/tmp/$name.outside.scylla" | python3 -c 'import json,sys;d=json.load(sys.stdin);d.pop("name");print(json.dumps(d))'; } >"$RUN/tmp/$name.cli.outside"
    diff "$RUN/tmp/$name.cli.inside" "$RUN/tmp/$name.cli.outside" >"$RUN/cli/$name.diff" || true
    # DECOMPILATION: the decompile verb's output (inside) vs the raw DumpDecomp.java dump (outside),
    # byte-exact C per function. A missing leg is reported as n/a, never as parity.
    d=n/a
    if [ -s "$RUN/decomp-inside/$name.decomp.json" ] && [ -s "$RUN/outside/decomp/$name.decomp.txt" ]; then
      if "$ABTEST" decomp --json "$RUN/decomp-inside/$name.decomp.json" "$RUN/outside/decomp/$name.decomp.txt" >"$RUN/decomp-compare/$name.json"; then d=PARITY; else d=DIFFERS; fi
    fi
    v=PARITY; [ $rc -eq 0 ] || v=DIFFERS
    m="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["masked"]))' "$RUN/compare/$name.json")"
    c=n/a; [ -s "$RUN/control/$name.json" ] && c="$(python3 -c 'import json,sys;print("deterministic" if json.load(open(sys.argv[1]))["parity"] else "DRIFTS")' "$RUN/control/$name.json")"
    k=identical; [ -s "$RUN/cli/$name.diff" ] && k=DIFFERS
    log "  $name: $v  masked=$m  control=$c  cli=$k  decomp=$d  raw-runs=${#raw[@]}"
  done
fi
if has report; then
  python3 - "$RUN" "$GHIDRA_DIST" "$REPO" <<'PY'
import json,sys,socket,subprocess,datetime,glob,os
run,dist,repo=sys.argv[1:4]
notes=[]
for lg in sorted(glob.glob(os.path.join(run,"outside","log","*.snapshot.log"))):
    n=os.path.basename(lg)[:-13]
    if not os.path.exists(os.path.join(run,"outside",n+".snapshot.json")):
        tail=open(lg,errors="replace").read().strip().splitlines()[-3:]
        notes.append(f"outside leg FAILED on `{n}`: `{' | '.join(t[:160] for t in tail)}`")
for lg in sorted(glob.glob(os.path.join(run,"outside","log","*.snapshot.log"))):
    n=os.path.basename(lg)[:-13]
    txt=open(lg,errors="replace").read()
    if "Go analysis failure" in txt:
        ver=[l for l in txt.splitlines() if "Go version" in l]
        notes.append(f"`{n}`: the engine's GolangSymbolAnalyzer failed on this binary (`{ver[0].strip()[:60] if ver else 'version unknown'}` -> `InvocationTargetException`): the dist's Go struct definitions do not cover this Go release. Function names still came from the ELF symtab, and BOTH legs report the identical partial result, so it is at parity — but a stripped Go binary of this release would lose its names on both legs.")
for lg in sorted(glob.glob(os.path.join(run,"inside","log","*.inside.log"))):
    n=os.path.basename(lg)[:-11]
    if not os.path.exists(os.path.join(run,"inside",n+".scylla")):
        tail=open(lg,errors="replace").read().strip().splitlines()[-2:]
        notes.append(f"inside leg FAILED on `{n}`: `{' | '.join(t[:200] for t in tail)}`")
for lg in sorted(glob.glob(os.path.join(run,"decomp-inside","log","*.inside.log"))):
    n=os.path.basename(lg)[:-11]
    dj=os.path.join(run,"decomp-inside",n+".decomp.json")
    if not (os.path.exists(dj) and os.path.getsize(dj) > 0):
        tail=open(lg,errors="replace").read().strip().splitlines()[-2:]
        notes.append(f"decomp leg FAILED on `{n}`: `{' | '.join(t[:200] for t in tail)}`")
meta={"date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip(),"host":socket.gethostname(),
      "dist":os.path.basename(dist),"scylla_rev":subprocess.run(["git","-C",repo,"rev-parse","--short","HEAD"],capture_output=True,text=True).stdout.strip(),
      "notes":notes}
json.dump(meta,open(os.path.join(run,"meta.json"),"w"),indent=1)
PY
  python3 "$HERE/report.py" "$RUN" "$RUN/REPORT.md"
  cp "$RUN/REPORT.md" "$REPO/abtest/REPORT.md"; cp "$RUN/REPORT-all.md" "$REPO/abtest/REPORT-all.md"
fi
if has baselines && [ "${NO_BASELINES:-0}" != 1 ]; then
  log "baselines -> abtest/baselines (only pairs that produced BOTH legs)"
  B="$REPO/abtest/baselines"; mkdir -p "$B/outside" "$B/inside" "$B/decomp" "$B/decomp-inside" "$B/nondeterministic"
  # The COMMITTED baseline set is a small, stable REPRESENTATIVE subset (REPRESENTATIVE.txt) — the
  # offline cargo-test parity gate replays exactly these. The full corpus + full baselines are NOT
  # committed (reproducible via ab.sh); a run refreshes the representative pairs in place.
  REPR="$B/REPRESENTATIVE.txt"
  is_repr() { [ -f "$REPR" ] || return 0; grep -qxF "$1" "$REPR"; }   # no manifest => commit all (back-compat)
  for f in "$B"/outside/* "$B"/inside/* "$B"/decomp/* "$B"/decomp-inside/* "$B"/nondeterministic/*; do
    [ -e "$f" ] || continue
    bn="$(basename "$f")"; bn="${bn%.snapshot.json.gz}"; bn="${bn%.scylla.gz}"; bn="${bn%.decomp.txt}"; bn="${bn%.decomp.json.gz}"; bn="${bn%.json}"
    { [ -f "$REPO/abtest/corpus/bin/$bn" ] && is_repr "$bn"; } || rm -f "$f"
  done
  for snap in "$RUN"/outside/*.elf.snapshot.json; do
    name="$(basename "$snap" .snapshot.json)"
    [ -s "$RUN/inside/$name.scylla" ] || continue
    is_repr "$name" || continue
    # gzipped, -n for a timestamp-free (reproducible) member; the tools read .gz in place
    rm -f "$B/outside/$name.snapshot.json" "$B/inside/$name.scylla"
    gzip -n -9 -c "$snap" >"$B/outside/$name.snapshot.json.gz"
    gzip -n -9 -c "$RUN/inside/$name.scylla" >"$B/inside/$name.scylla.gz"
    [ -s "$RUN/outside/decomp/$name.decomp.txt" ] && cp "$RUN/outside/decomp/$name.decomp.txt" "$B/decomp/$name.decomp.txt"
    # the decompile-verb leg rides beside the raw dump it is gated against (tests/parity.rs)
    rm -f "$B/decomp-inside/$name.decomp.json.gz"
    [ -s "$RUN/decomp-inside/$name.decomp.json" ] && gzip -n -9 -c "$RUN/decomp-inside/$name.decomp.json" >"$B/decomp-inside/$name.decomp.json.gz"
    # the engine-nondeterminism record rides with the pair ONLY when it names at least one function
    rm -f "$B/nondeterministic/$name.json"
    if [ -s "$RUN/flaky/$name.json" ] && [ "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["functions"]))' "$RUN/flaky/$name.json")" != 0 ]; then
      cp "$RUN/flaky/$name.json" "$B/nondeterministic/$name.json"
    fi
  done
  log "  $(ls "$B/inside" | wc -l) pairs recorded"
fi
log "done: $RUN"
