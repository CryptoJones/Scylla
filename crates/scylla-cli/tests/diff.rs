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
