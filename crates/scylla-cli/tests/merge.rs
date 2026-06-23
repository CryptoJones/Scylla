//! Integration tests for `scylla merge`: run the REAL binary to carry annotations from one artifact
//! onto a re-analysis (DD-005), then confirm via `scylla functions` that the rename followed across
//! the fresh-id rebuild. Zero deps (std only).

use std::process::Command;

const ANNOTATED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_annotated.scylla"
);
const REBUILT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_rebuilt.scylla"
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
fn merge_carries_annotations_onto_a_reanalysis() {
    // mathlib_annotated has gcd renamed to euclid_gcd; mathlib_rebuilt is a fresh-id re-analysis with
    // the original `gcd`. After merge, the rename re-anchors onto the rebuild by structural identity.
    let out = std::env::temp_dir().join(format!("scylla-cli-merge-{}.scylla", std::process::id()));
    let out_path = out.to_str().unwrap();
    let (code, _o) = run(&["merge", ANNOTATED, REBUILT, out_path]);
    assert_eq!(code, 0, "merge exit 0");

    let (code2, listing) = run(&["functions", out_path]);
    assert_eq!(code2, 0);
    assert!(
        listing.contains("euclid_gcd"),
        "rename carried across the rebuild: {listing}"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn merge_bad_usage_exits_2() {
    let (code, _o) = run(&["merge", ANNOTATED, REBUILT]); // missing the output path
    assert_eq!(code, 2, "wrong arg count -> usage, exit 2");
}

#[test]
fn merge_missing_input_is_trouble_exit_2() {
    let out =
        std::env::temp_dir().join(format!("scylla-cli-merge-x-{}.scylla", std::process::id()));
    let (code, _o) = run(&[
        "merge",
        "/no/such/artifact.scylla",
        REBUILT,
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "unreadable input -> exit 2");
}
