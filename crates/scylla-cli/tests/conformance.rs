//! Contract-conformance for the CLI head (Sprint 9, DD-017): the binary is a *thin projection* of
//! the client port — "many heads, one body" — so its `--json` output must equal what
//! `scylla_port::Session` computes for the SAME artifact, verb by verb. We do NOT hardcode golden
//! numbers (those live in `inspect.rs`/`diff.rs`); we derive the expectation from the port in-process
//! and assert the head reproduces it. If a head ever drifts from the body, these fail.

use std::process::Command;

use scylla_model::StableId;
use scylla_port::{Session, Zoom};

const BASE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);
const PATCHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_patched.scylla"
);

/// Run the real binary, returning `(exit code, stdout)`.
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

/// Run a `--json` verb and parse stdout; asserts exit 0 and valid JSON.
fn json(args: &[&str]) -> serde_json::Value {
    let (code, out) = run(args);
    assert_eq!(code, 0, "`{args:?}` should exit 0");
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("`{args:?}` should emit JSON: {e}\n{out}"))
}

/// The port, loaded the same way every head loads it — the source of truth for the contract.
fn port(path: &str) -> Session {
    Session::from_artifact(&std::fs::read(path).expect("read artifact")).expect("load artifact")
}

/// gcd's stable id, resolved through the port (robust to id re-mint).
fn id_of(p: &Session, name: &str) -> StableId {
    p.functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name} present in the sample"))
        .id
}

#[test]
fn cli_info_matches_the_port() {
    let p = port(BASE);
    let prog = p.program();
    let v = json(&["info", "--json", BASE]);
    assert_eq!(v["name"], serde_json::json!(prog.name), "name");
    assert_eq!(v["language"], serde_json::json!(prog.language), "language");
    assert_eq!(
        v["functions"].as_u64().expect("functions is a number") as usize,
        prog.functions.len(),
        "function count matches the port"
    );
}

#[test]
fn cli_functions_matches_the_port() {
    let p = port(BASE);
    let mut expected: Vec<String> = p
        .functions(Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();

    let v = json(&["functions", "--json", BASE]);
    let mut got: Vec<String> = v
        .as_array()
        .expect("an array")
        .iter()
        .map(|f| f["name"].as_str().expect("name is a string").to_string())
        .collect();
    got.sort();

    assert_eq!(got, expected, "the CLI lists exactly the port's functions");
}

#[test]
fn cli_view_matches_the_port() {
    let p = port(BASE);
    let id = id_of(&p, "gcd");
    let pv = p.view(id, Zoom::Detail).expect("port view");

    let v = json(&["view", "--json", BASE, &id.0.to_string(), "detail"]);
    assert_eq!(v["name"], serde_json::json!(pv.name), "name");
    assert_eq!(
        v["bb_count"].as_u64(),
        pv.bb_count.map(|b| b as u64),
        "blocks"
    );
    let got_callers: Vec<String> = v["callers"]
        .as_array()
        .expect("callers array")
        .iter()
        .map(|c| c.as_str().expect("caller name").to_string())
        .collect();
    assert_eq!(
        got_callers,
        pv.callers.clone().unwrap_or_default(),
        "view callers match the port"
    );
}

#[test]
fn cli_callers_verb_matches_the_port() {
    let p = port(BASE);
    let prog = p.program();
    let id = id_of(&p, "gcd");

    let mut expected: Vec<String> = p
        .callers(id)
        .into_iter()
        .map(|c| prog.display_name(c).unwrap_or_default())
        .collect();
    expected.sort();

    let (code, out) = run(&["callers", BASE, &id.0.to_string()]);
    assert_eq!(code, 0, "callers exit 0");
    let mut got: Vec<String> = out
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .map(str::to_string)
        .collect();
    got.sort();

    assert_eq!(got, expected, "the `callers` verb matches the port");
}

#[test]
fn cli_diff_matches_the_port() {
    let a = port(BASE);
    let b = port(PATCHED);
    let d = a.diff(&b);
    let renamed = d.matched.iter().filter(|(x, y)| x != y).count();
    let unchanged = d.matched.len() - renamed;

    // `diff` follows `git diff --exit-code`: 0 if identical, 1 if they differ (the case here), 2 on
    // trouble — so accept 1, don't demand 0, then parse the report from stdout.
    let (code, out) = run(&["diff", "--json", BASE, PATCHED]);
    assert!(matches!(code, 0 | 1), "diff exit 0/1, got {code}");
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("diff emits JSON: {e}\n{out}"));
    assert_eq!(
        v["unchanged"].as_u64().expect("unchanged is a number") as usize,
        unchanged,
        "unchanged count matches the port"
    );
    assert_eq!(
        v["modified"].as_array().expect("modified array").len(),
        d.changed.len(),
        "modified count matches the port"
    );
    assert_eq!(
        v["added"].as_array().expect("added array").len(),
        d.only_there.len(),
        "added count matches the port"
    );
    assert_eq!(
        v["removed"].as_array().expect("removed array").len(),
        d.only_here.len(),
        "removed count matches the port"
    );
}
