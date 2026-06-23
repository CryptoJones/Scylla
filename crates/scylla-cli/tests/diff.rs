//! Integration tests for `scylla diff`: run the REAL binary (`CARGO_BIN_EXE_scylla`) over the
//! committed sample artifacts and assert the report + `git diff --exit-code` semantics. Zero deps.

use std::process::Command;

// Committed sample artifacts (this crate's manifest dir is crates/scylla-cli).
const BASE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);
const PATCHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_patched.scylla"
);

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_scylla"))
        .args(args)
        .output()
        .expect("run scylla");
    let code = out.status.code().unwrap_or(-1);
    (code, String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn diff_of_identical_artifacts_is_clean_exit_0() {
    let (code, out) = run(&["diff", BASE, BASE]);
    assert_eq!(code, 0, "identical artifacts -> exit 0");
    assert!(out.contains("no differences"), "stdout: {out}");
    assert!(out.contains("0 modified"));
}

#[test]
fn diff_reports_a_modified_function_exit_1() {
    // mathlib_patched has gcd's body edited (edges intact) -> reported MODIFIED, not added+removed.
    let (code, out) = run(&["diff", BASE, PATCHED]);
    assert_eq!(
        code, 1,
        "differing artifacts -> exit 1 (git diff --exit-code)"
    );
    assert!(out.contains("1 modified"), "summary: {out}");
    assert!(
        out.contains("modified:") && out.contains("gcd"),
        "modified section: {out}"
    );
    assert!(
        out.contains("0 added") && out.contains("0 removed"),
        "not a spurious add/remove: {out}"
    );
}

#[test]
fn diff_of_a_missing_file_is_trouble_exit_2() {
    let (code, _out) = run(&["diff", "/no/such/artifact.scylla", BASE]);
    assert_eq!(
        code, 2,
        "unreadable input -> exit 2 (trouble, distinct from 1)"
    );
}

#[test]
fn bad_usage_exits_2() {
    let (code, _out) = run(&["diff", BASE]); // missing second arg
    assert_eq!(code, 2, "wrong arg count -> usage, exit 2");
}

#[test]
fn diff_json_emits_structured_output() {
    let (code, out) = run(&["diff", "--json", BASE, PATCHED]);
    assert_eq!(code, 1, "differing -> exit 1 even in json mode");
    assert!(
        out.contains("\"differs\": true"),
        "json differs flag: {out}"
    );
    assert!(
        out.contains("\"modified\""),
        "json has a modified array: {out}"
    );
    assert!(out.contains("gcd"), "names gcd: {out}");
    assert!(out.contains("\"unchanged\": 12"), "12 unchanged: {out}");
}

#[test]
fn diff_reports_a_match_confidence_breakdown() {
    // Identical artifacts: every function is recovered by the most confident rung — EXACT.
    let (_, out) = run(&["diff", BASE, BASE]);
    assert!(
        out.contains("matched by: 13 exact"),
        "confidence breakdown by ladder rung: {out}"
    );

    // The patched build (gcd's body edited) exposes the breakdown in JSON too: the unchanged pairs
    // are `exact`; gcd is recovered by a softer rung (so it is NOT counted as exact).
    let (_, json) = run(&["diff", "--json", BASE, PATCHED]);
    assert!(
        json.contains("\"methods\""),
        "json has a methods object: {json}"
    );
    assert!(
        json.contains("\"exact\""),
        "the unchanged pairs are exact: {json}"
    );
}

#[test]
fn diff_json_of_identical_is_not_differing_exit_0() {
    let (code, out) = run(&["diff", "--json", BASE, BASE]);
    assert_eq!(code, 0, "identical -> exit 0 in json mode");
    assert!(
        out.contains("\"differs\": false"),
        "json differs=false: {out}"
    );
}
