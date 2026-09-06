//! `scylla-abtest compare [--json] [--ignore <flaky.json>] <inside.scylla> <outside.snapshot.json>`
//! `scylla-abtest flaky <out.json> <run1.snapshot.json> <run2.snapshot.json> [...]`
//! `scylla-abtest decomp [--json] <inside.decomp.json> <outside.decomp.txt>`
//!
//! Exit codes follow `scylla diff` / `git diff --exit-code`: 0 = parity, 1 = the legs differ,
//! 2 = trouble (unreadable input). See `abtest/README.md`.

use std::collections::BTreeSet;
use std::process::ExitCode;

use scylla_port::Session;

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().collect();
    let json = raw.iter().any(|a| a == "--json");
    // `--ignore <flaky.json>`: the engine-nondeterminism mask (from `flaky`).
    let mut ignore: Option<String> = None;
    let mut args: Vec<&String> = Vec::new();
    let mut it = raw.iter().filter(|a| *a != "--json");
    while let Some(a) = it.next() {
        if a == "--ignore" {
            ignore = it.next().cloned();
        } else {
            args.push(a);
        }
    }
    match args.get(1).map(|s| s.as_str()) {
        Some("compare") if args.len() == 4 => compare(args[2], args[3], ignore.as_deref(), json),
        Some("flaky") if args.len() >= 5 => flaky(args[2], &args[3..]),
        Some("decomp") if args.len() == 4 => decomp(args[2], args[3], json),
        _ => {
            eprintln!(
                "usage: {p} compare [--json] [--ignore <flaky.json>] <inside.scylla> <outside.snapshot.json>\n       \
                 {p} flaky <out.json> <run1.snapshot.json> <run2.snapshot.json> [...]\n       \
                 {p} decomp [--json] <inside.decomp.json> <outside.decomp.txt>\n\n  \
                 compare — A/B parity: the Scylla-materialized artifact (inside) vs the raw engine \
                 headless snapshot (outside); exit 0 parity, 1 differs, 2 trouble\n  \
                 flaky   — characterize ENGINE nondeterminism: the functions that differ across several \
                 direct engine runs of one binary (the only legitimate source of --ignore)\n  \
                 decomp  — decompilation parity: `scylla decompile --json` through Scylla (inside) vs \
                 the raw engine's DumpDecomp.java text (outside), byte-exact C per function; \
                 exit 0/1/2 as compare",
                p = args.first().map(|s| s.as_str()).unwrap_or("scylla-abtest")
            );
            ExitCode::from(2)
        }
    }
}

fn read_snapshot(path: &str) -> Result<scylla_model::Program, ExitCode> {
    let bytes = scylla_abtest::read_maybe_gz(std::path::Path::new(path)).map_err(|e| {
        eprintln!("error: reading {path}: {e}");
        ExitCode::from(2)
    })?;
    let snapshot = String::from_utf8_lossy(&bytes);
    scylla_ingest::snapshot_to_program(&snapshot).map_err(|e| {
        eprintln!("error: parsing {path}: {e}");
        ExitCode::from(2)
    })
}

fn flaky(out_path: &str, run_paths: &[&String]) -> ExitCode {
    let mut runs = Vec::new();
    for p in run_paths {
        match read_snapshot(p) {
            Ok(prog) => runs.push(prog),
            Err(code) => return code,
        }
    }
    let f = scylla_abtest::flaky(&runs);
    let text = serde_json::to_string_pretty(&f).expect("a Flaky serializes infallibly");
    if let Err(e) = std::fs::write(out_path, text) {
        eprintln!("error: writing {out_path}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "scylla-abtest flaky: {} runs, {} engine-nondeterministic function(s) -> {out_path}",
        f.runs,
        f.functions.len()
    );
    for r in &f.functions {
        println!(
            "  {} {:?} {:?} variants={:?}",
            r.addr, r.names, r.fields, r.variants
        );
    }
    ExitCode::SUCCESS
}

fn compare(inside_path: &str, outside_path: &str, ignore: Option<&str>, json: bool) -> ExitCode {
    let inside_bytes = match scylla_abtest::read_maybe_gz(std::path::Path::new(inside_path)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: reading {inside_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let inside = match Session::from_artifact(&inside_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: loading {inside_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let outside = match read_snapshot(outside_path) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let mask: BTreeSet<u64> = match ignore {
        None => BTreeSet::new(),
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|t| {
                serde_json::from_str::<scylla_abtest::Flaky>(&t).map_err(|e| e.to_string())
            }) {
            Ok(f) => f.mask(),
            Err(e) => {
                eprintln!("error: reading mask {p}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    let report = scylla_abtest::compare_masked(inside.program(), &outside, &mask);
    if json {
        let mut v = serde_json::to_value(&report).expect("a Report serializes infallibly");
        v["inside"] = serde_json::Value::String(inside_path.to_string());
        v["outside"] = serde_json::Value::String(outside_path.to_string());
        v["parity"] = serde_json::Value::Bool(report.is_parity());
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("a JSON Value serializes infallibly")
        );
    } else {
        println!("scylla-abtest: {inside_path}  vs  {outside_path}");
        println!(
            "  functions: inside {}  outside {}",
            report.functions_inside, report.functions_outside
        );
        if let Some((a, b)) = &report.language_mismatch {
            println!("  LANGUAGE MISMATCH: inside {a:?} outside {b:?}");
        }
        for a in &report.only_inside {
            println!("  only inside:  {a:#x}");
        }
        for a in &report.only_outside {
            println!("  only outside: {a:#x}");
        }
        for m in &report.field_mismatches {
            println!(
                "  {:#x} {} .{}: inside {} | outside {}",
                m.addr, m.name, m.field, m.inside, m.outside
            );
        }
        for p in &report.projection_mismatches {
            println!("  projection: {p}");
        }
        println!(
            "  verdict: {}",
            if report.is_parity() {
                "PARITY"
            } else {
                "DIFFERS"
            }
        );
    }
    if report.is_parity() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn decomp(inside_path: &str, outside_path: &str, json: bool) -> ExitCode {
    let read = |p: &str| -> Result<String, ExitCode> {
        scylla_abtest::read_maybe_gz(std::path::Path::new(p))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .map_err(|e| {
                eprintln!("error: reading {p}: {e}");
                ExitCode::from(2)
            })
    };
    let (inside_text, outside_text) = match (read(inside_path), read(outside_path)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(c), _) | (_, Err(c)) => return c,
    };
    let inside = match scylla_abtest::decomp::parse_inside(&inside_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: parsing {inside_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let outside = match scylla_abtest::decomp::parse_baseline(&outside_text) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: parsing {outside_path}: {e}");
            return ExitCode::from(2);
        }
    };
    let report = scylla_abtest::decomp::compare_decomp(&inside, &outside.functions);
    if json {
        let mut v = serde_json::to_value(&report).expect("a DecompReport serializes infallibly");
        v["inside"] = serde_json::Value::String(inside_path.to_string());
        v["outside"] = serde_json::Value::String(outside_path.to_string());
        v["parity"] = serde_json::Value::Bool(report.is_parity());
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("a JSON Value serializes infallibly")
        );
    } else {
        println!("scylla-abtest decomp: {inside_path}  vs  {outside_path}");
        println!(
            "  functions: inside {}  outside {}",
            report.functions_inside, report.functions_outside
        );
        for a in &report.only_inside {
            println!("  only inside:  {a:#x}");
        }
        for a in &report.only_outside {
            println!("  only outside: {a:#x}");
        }
        for m in &report.field_mismatches {
            println!("  {:#x} {} .{}: differs", m.addr, m.name, m.field);
        }
        println!(
            "  verdict: {}",
            if report.is_parity() {
                "PARITY"
            } else {
                "DIFFERS"
            }
        );
    }
    if report.is_parity() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
