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

/// gcd's stable id in the committed sample, looked up via `functions` (robust to re-mint).
fn gcd_id() -> String {
    let (_, out) = run(&["functions", BASE]);
    out.lines()
        .find(|l| l.split('\t').nth(1) == Some("gcd"))
        .and_then(|l| l.split('\t').next())
        .expect("gcd is in the sample")
        .to_string()
}

#[test]
fn view_shows_one_function_at_detail() {
    let (code, out) = run(&["view", BASE, &gcd_id(), "detail"]);
    assert_eq!(code, 0, "view exit 0");
    assert!(
        out.contains("name:") && out.contains("gcd"),
        "names gcd: {out}"
    );
    assert!(
        out.contains("address:"),
        "detail zoom shows the address: {out}"
    );
    assert!(
        out.contains("callers: main"),
        "gcd is called by main: {out}"
    );
}

#[test]
fn callers_lists_the_calling_functions() {
    let (code, out) = run(&["callers", BASE, &gcd_id()]);
    assert_eq!(code, 0, "callers exit 0");
    assert!(out.contains("main"), "gcd's caller is main: {out}");
}

#[test]
fn view_of_an_unknown_id_is_trouble_exit_2() {
    let (code, _out) = run(&["view", BASE, "999999"]);
    assert_eq!(code, 2, "unknown id -> exit 2");
}

#[test]
fn callers_of_a_non_integer_id_is_trouble_exit_2() {
    let (code, _out) = run(&["callers", BASE, "abc"]);
    assert_eq!(code, 2, "non-integer id -> exit 2");
}

#[test]
fn info_json_emits_an_object() {
    let (code, out) = run(&["info", "--json", BASE]);
    assert_eq!(code, 0);
    assert!(
        out.contains("\"functions\": 13"),
        "json function count: {out}"
    );
    assert!(out.contains("\"name\""), "json has a name field: {out}");
}

#[test]
fn functions_json_emits_an_array() {
    let (code, out) = run(&["functions", "--json", BASE]);
    assert_eq!(code, 0);
    assert!(out.trim_start().starts_with('['), "a json array: {out}");
    assert!(out.contains("\"name\": \"gcd\""), "lists gcd: {out}");
}

#[test]
fn view_json_emits_an_object() {
    let (code, out) = run(&["view", "--json", BASE, &gcd_id()]);
    assert_eq!(code, 0);
    assert!(out.contains("\"name\": \"gcd\""), "names gcd: {out}");
    assert!(out.contains("\"callers\""), "has a callers field: {out}");
}

#[test]
fn search_finds_functions_by_substring() {
    // case-insensitive substring; tab-separated like `functions`.
    let (code, out) = run(&["search", BASE, "GC"]);
    assert_eq!(code, 0, "search exit 0");
    let names: Vec<&str> = out.lines().filter_map(|l| l.split('\t').nth(1)).collect();
    assert_eq!(names, vec!["gcd"], "case-insensitive gcd: {out}");
    // a miss is empty output, exit 0 (not an error).
    let (code, out) = run(&["search", BASE, "no-such-fn"]);
    assert_eq!(code, 0, "a miss is exit 0");
    assert!(out.trim().is_empty(), "a miss is empty: {out:?}");
}
