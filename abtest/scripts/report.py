#!/usr/bin/env python3
"""report.py <run-dir> <out REPORT.md> — render the A/B parity run into a Markdown report.

Reads, per binary, <run-dir>/compare/<bin>.json (scylla-abtest compare --json, inside vs outside),
<run-dir>/control/<bin>.json (outside vs outside-repeat: engine determinism),
<run-dir>/cli/<bin>.diff (the CLI-level byte check), and <run-dir>/decomp-compare/<bin>.json
(scylla-abtest decomp --json: the decompile verb vs the raw decompiler dump). Never hides a
difference: every non-parity row is listed with its first mismatches.
"""
import glob, json, os, re, sys, datetime

run, out = sys.argv[1], sys.argv[2]
TC = {"gcc": "C (gcc)", "clang": "C (clang)", "gxx": "C++ (g++)", "clangxx": "C++ (clang++)",
      "go122": "Go 1.22", "go126": "Go 1.26", "rustc": "Rust"}
meta = json.load(open(os.path.join(run, "meta.json")))
rows, details = [], []
names = sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(run, "compare", "*.json")))
missing = sorted(set(os.path.basename(p) for p in glob.glob(os.path.join(run, "outside", "*.elf.snapshot.json")))
                 - {n + ".snapshot.json" for n in names})
n_par = n_ctl = n_dec = 0
for n in names:
    c = json.load(open(os.path.join(run, "compare", n + ".json")))
    ctl_p = os.path.join(run, "control", n + ".json")
    ctl = json.load(open(ctl_p)) if os.path.exists(ctl_p) else None
    cli_p = os.path.join(run, "cli", n + ".diff")
    cli = (os.path.getsize(cli_p) == 0) if os.path.exists(cli_p) else None
    cli_masked_only = False
    if cli is False and c["masked"]:
        # every changed CLI line must belong to a masked function (`"summary": "<name> — …"`)
        masked_names = {m["name"] for m in c["masked"]}
        changed = [l for l in open(cli_p, errors="replace") if l[:1] in "<>"]
        def owner(line):
            m_ = re.search(r'"summary": "(.*?) — ', line)
            return m_.group(1) if m_ else None
        cli_masked_only = bool(changed) and all(owner(l) in masked_names for l in changed)
    par = c["parity"]; n_par += par
    dec_p = os.path.join(run, "decomp-compare", n + ".json")
    dec = json.load(open(dec_p)) if os.path.exists(dec_p) else None
    dec_ok = dec["parity"] if dec else None; n_dec += bool(dec_ok)
    ctl_ok = ctl["parity"] if ctl else None; n_ctl += bool(ctl_ok)
    fl_p = os.path.join(run, "flaky", n + ".json")
    fl = json.load(open(fl_p)) if os.path.exists(fl_p) else None
    notes = []
    if c["masked"]:
        notes.append("engine-nondeterministic, masked: " + ", ".join(f"`{m['name']}`" for m in c["masked"][:4])
                     + (f" (+{len(c['masked'])-4})" if len(c["masked"]) > 4 else "")
                     + (f" — over {fl['runs']} raw runs" if fl else ""))
    if not par:
        notes.append(f"{len(c['field_mismatches'])} field, {len(c['only_inside'])}/{len(c['only_outside'])} only-in/only-out, {len(c['projection_mismatches'])} projection")
        first = c["field_mismatches"][:5]
        details.append((n, c, first))
    if ctl is not None and not ctl_ok:
        notes.append("ENGINE NONDETERMINISTIC across two raw runs")
    if cli is False and not cli_masked_only:
        notes.append("CLI JSON differs")
    if dec is not None and not dec_ok:
        notes.append(f"DECOMP differs: {len(dec['only_inside'])}/{len(dec['only_outside'])} only-in/only-out, {len(dec['field_mismatches'])} field")
        details.append((n + " (decomp)", {"language_mismatch": None, "only_inside": dec["only_inside"], "only_outside": dec["only_outside"], "projection_mismatches": []},
                        dec["field_mismatches"][:5]))
    lang = n.split(".")[1] if "." in n else "?"
    rows.append((n, TC.get(lang, lang),
                 c["functions_inside"], c["functions_outside"],
                 ("PARITY" if par else "**DIFFERS**") + (f" ({len(c['masked'])} masked)" if c["masked"] else ""),
                 {None: "n/a", True: "deterministic", False: "**drifts**"}[ctl_ok],
                 "identical (masked fns aside)" if cli_masked_only else {None: "n/a", True: "identical", False: "**differs**"}[cli],
                 {None: "n/a", True: f"PARITY ({dec['functions_inside']} fns)" if dec else "n/a", False: "**DIFFERS**"}[dec_ok],
                 "; ".join(notes)))

L = []
L.append("# A/B parity report — inside Scylla vs raw engine headless\n")
L.append(f"Run: {meta['date']} on {meta['host']} · engine dist: `{meta['dist']}` · scylla `{meta['scylla_rev']}` · "
         f"{len(names)} binaries compared, {n_par} at parity, control deterministic on {n_ctl}, "
         f"decompilation at parity on {n_dec} of {sum(1 for r in rows if r[7] != 'n/a')} with a decomp leg.\n")
L.append("Inside = `scylla materialize` through the sandboxed engine-service (DD-034 container, gRPC over a Unix socket) → `.scylla`. "
         "Outside = the same dist's `support/analyzeHeadless` run directly on the host with the same `dump_model.java`. "
         "Control = the outside leg run again (engine determinism; a function the RAW engine reports two different ways across direct runs "
         "is engine nondeterminism, not a wrapper fault — such functions are *masked* from the field checks, listed by name, and "
         "recorded in `baselines/nondeterministic/`). CLI = `scylla functions/info --json` on the inside artifact vs on a "
         "`scylla-ingest` of the outside snapshot (byte-identical except the program name). Decomp = `scylla decompile --json` "
         "through the sandbox (the `Decompile` RPC) vs the raw engine's own `DumpDecomp.java` dump: the decompiled C, prototype "
         "and calling convention must be byte-identical per function. Verdict rules: PARITY only when every "
         "function, every field, and the client-port projection agree.\n")
# Summary by toolchain first — the per-binary table (k >= 1024 rows) goes to REPORT-all.md.
agg = {}
for r in rows:
    a = agg.setdefault(r[1], {"n": 0, "parity": 0, "masked": 0, "det": 0, "fns": 0, "dec_n": 0, "dec_ok": 0, "dec_fns": 0})
    a["n"] += 1; a["parity"] += r[4].startswith("PARITY"); a["det"] += r[5] == "deterministic"; a["fns"] += r[3]
    a["masked"] += int(r[4].split("(")[1].split()[0]) if "(" in r[4] else 0
    if r[7] != "n/a":
        a["dec_n"] += 1; a["dec_ok"] += r[7].startswith("PARITY")
        a["dec_fns"] += int(r[7].split("(")[1].split()[0]) if r[7].startswith("PARITY") else 0
L.append("## Summary by toolchain\n")
L.append("| toolchain | binaries | at parity | functions compared | engine-deterministic on first control | engine-nondeterministic fns masked | decomp legs | decomp at parity | functions decompiled |")
L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
for tc in sorted(agg):
    a = agg[tc]
    L.append(f"| {tc} | {a['n']} | {a['parity']} | {a['fns']} | {a['det']} | {a['masked']} | {a['dec_n']} | {a['dec_ok']} | {a['dec_fns']} |")
L.append(f"| **all** | **{len(rows)}** | **{n_par}** | **{sum(a['fns'] for a in agg.values())}** | **{n_ctl}** | **{sum(a['masked'] for a in agg.values())}** | "
         f"**{sum(a['dec_n'] for a in agg.values())}** | **{n_dec}** | **{sum(a['dec_fns'] for a in agg.values())}** |")
HDR = "| binary | toolchain | fns inside | fns outside | inside vs outside | control | CLI JSON | decomp | notes |\n|---|---|---:|---:|---|---|---|---|---|"
odd = [r for r in rows if not (r[4] == "PARITY" and r[6] == "identical" and (r[7] == "n/a" or r[7].startswith("PARITY")))]
L.append("\n## Binaries needing a second look\n")
if odd:
    L.append("Every row that is not a plain PARITY with byte-identical CLI output and decompilation parity (where a decomp leg ran). The full per-binary table is in `REPORT-all.md`.\n")
    L.append(HDR)
    for r in odd:
        L.append("| `%s` | %s | %d | %d | %s | %s | %s | %s | %s |" % r)
else:
    L.append("None — every binary is a plain PARITY with byte-identical CLI output and decompilation parity where a decomp leg ran. The full per-binary table is in `REPORT-all.md`.")
A = ["# A/B parity report — every binary\n", f"Run: {meta['date']} · {len(rows)} binaries. Summary and findings: `REPORT.md`.\n", HDR]
for r in rows:
    A.append("| `%s` | %s | %d | %d | %s | %s | %s | %s | %s |" % r)
open(os.path.join(os.path.dirname(out), "REPORT-all.md"), "w").write("\n".join(A) + "\n")
if missing:
    L.append("\n## Not compared\n")
    for m in missing:
        L.append(f"- `{m[:-14]}` — one leg did not produce output (see the run log). ")
if details:
    L.append("\n## Mismatch detail\n")
    for n, c, first in details:
        L.append(f"### `{n}`\n")
        if c["language_mismatch"]:
            L.append(f"- language: inside `{c['language_mismatch'][0]}` outside `{c['language_mismatch'][1]}`")
        for a in c["only_inside"][:10]:
            L.append(f"- only inside: `{a:#x}`")
        for a in c["only_outside"][:10]:
            L.append(f"- only outside: `{a:#x}`")
        for m in first:
            L.append(f"- `{m['addr']:#x}` `{m['name']}` **{m['field']}**: inside `{m['inside'][:120]}` · outside `{m['outside'][:120]}`")
        for p in c["projection_mismatches"][:6]:
            L.append(f"- projection: `{p[:160]}`")
        L.append("")
masked_rows = [(n, json.load(open(os.path.join(run, "compare", n + ".json")))) for n in names]
masked_rows = [(n, c) for n, c in masked_rows if c["masked"]]
if masked_rows:
    L.append("\n## Engine nondeterminism (masked functions)\n")
    L.append("The RAW engine, run directly several times on the same bytes, reported these functions with different body "
             "extents. That is a property of the engine's auto-analysis, observed with no Scylla in the loop, so they cannot be "
             "evidence for or against the wrapper and are excluded from the field checks above. Every other function in those "
             "binaries is at parity.\n")
    L.append("| binary | function | fields that vary | (size, blocks) variants seen | raw runs |")
    L.append("|---|---|---|---|---:|")
    for n, c in masked_rows:
        fl_p = os.path.join(run, "flaky", n + ".json")
        fl = json.load(open(fl_p)) if os.path.exists(fl_p) else {"runs": "?", "functions": []}
        for rec in fl["functions"]:
            L.append(f"| `{n}` | `{'/'.join(rec['names'])}` @ {rec['addr']} | {', '.join(rec['fields'])} | "
                     f"{', '.join(f'({s}, {b})' for s, b in rec['variants'])} | {fl['runs']} |")
if meta.get("notes"):
    L.append("\n## Run notes\n")
    for x in meta["notes"]:
        L.append(f"- {x}")
L.append("\nRe-run: `GHIDRA_DIST=<dist> abtest/scripts/ab.sh` (see `abtest/README.md`).\n")
open(out, "w").write("\n".join(L))
print(f"report: {out} ({n_par}/{len(names)} parity)")
