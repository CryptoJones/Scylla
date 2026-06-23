//! Integration tests for `scylla info` / `scylla functions`: run the REAL binary over a committed
//! sample artifact and assert the offline inspector output + exit codes. Zero deps (std only).

use std::process::Command;

const BASE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_scylla"))
        .args(args)
        .output()
        .expect("run scylla");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn info_reports_artifact_metadata() {
    let (code, out) = run(&["info", BASE]);
    assert_eq!(code, 0, "info exit 0");
    assert!(out.contains("name:"), "has a name line: {out}");
    assert!(out.contains("language:"), "has a language line: {out}");
    assert!(
        out.contains("functions: 13"),
        "13 functions in the sample: {out}"
    );
}

#[test]
fn functions_lists_by_name_at_a_zoom() {
    let (code, out) = run(&["functions", BASE]);
    assert_eq!(code, 0, "functions exit 0");
    let names: Vec<&str> = out.lines().filter_map(|l| l.split('\t').nth(1)).collect();
    for expected in ["gcd", "fib", "main"] {
        assert!(names.contains(&expected), "lists {expected}: {out}");
    }
    // default listing is sorted by name (stable, greppable, diff-friendly)
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "functions are listed sorted by name");
}

#[test]
fn functions_accepts_a_zoom_argument() {
    let (code, out) = run(&["functions", BASE, "intent"]);
    assert_eq!(code, 0);
    assert!(out.contains("gcd"), "intent zoom still lists gcd: {out}");
}

#[test]
fn functions_rejects_an_unknown_zoom() {
    let (code, _out) = run(&["functions", BASE, "wat"]);
    assert_eq!(code, 2, "unknown zoom -> exit 2");
}

#[test]
fn info_of_a_missing_file_is_trouble_exit_2() {
    let (code, _out) = run(&["info", "/no/such/artifact.scylla"]);
    assert_eq!(code, 2, "unreadable input -> exit 2");
}
