//! Integration tests for `scylla --help` / `scylla --version` (USE-P3-1 / #37):
//! Assert that `-h`/`--help`/`help` prints usage to stdout and exits with code 0,
//! `-V`/`--version` prints version to stdout and exits with code 0,
//! and missing/unrecognized arguments print usage to stderr and exit with code 2.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_scylla"))
        .args(args)
        .output()
        .expect("run scylla");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_flag_exits_0_on_stdout() {
    for flag in ["--help", "-h", "help"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(code, 0, "{flag} should exit 0");
        assert!(
            stdout.contains("usage:"),
            "{flag} stdout should contain usage"
        );
        assert!(
            stdout.contains("materialize"),
            "{flag} stdout should describe verbs"
        );
        assert!(
            stdout.contains("-h, --help"),
            "{flag} stdout should mention --help"
        );
        assert!(
            stdout.contains("-V, --version"),
            "{flag} stdout should mention --version"
        );
        assert!(stderr.is_empty(), "{flag} stderr should be empty: {stderr}");
    }
}

#[test]
fn subcommand_help_exits_0_on_stdout() {
    for verb in [
        "info",
        "diff",
        "materialize",
        "decompile",
        "functions",
        "view",
        "callers",
        "merge",
    ] {
        let (code, stdout, stderr) = run(&[verb, "--help"]);
        assert_eq!(code, 0, "{verb} --help should exit 0");
        assert!(
            stdout.contains("usage:"),
            "{verb} --help stdout should contain usage"
        );
        assert!(
            stderr.is_empty(),
            "{verb} --help stderr should be empty: {stderr}"
        );
    }
}

#[test]
fn version_flag_exits_0_on_stdout() {
    for flag in ["--version", "-V"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(code, 0, "{flag} should exit 0");
        assert!(
            stdout.starts_with("scylla "),
            "{flag} stdout should start with 'scylla ': {stdout}"
        );
        let version = stdout.trim().strip_prefix("scylla ").unwrap();
        assert!(!version.is_empty(), "version string must not be empty");
        assert!(stderr.is_empty(), "{flag} stderr should be empty: {stderr}");
    }
}

#[test]
fn missing_args_exits_2_on_stderr() {
    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 2, "no args should exit 2");
    assert!(
        stdout.is_empty(),
        "no args stdout should be empty: {stdout}"
    );
    assert!(
        stderr.contains("usage:"),
        "no args stderr should contain usage"
    );
}

#[test]
fn unrecognized_args_exits_2_on_stderr() {
    let (code, stdout, stderr) = run(&["unrecognized-verb"]);
    assert_eq!(code, 2, "unrecognized verb should exit 2");
    assert!(
        stdout.is_empty(),
        "unrecognized verb stdout should be empty: {stdout}"
    );
    assert!(
        stderr.contains("usage:"),
        "unrecognized verb stderr should contain usage"
    );
}

#[test]
fn search_help_vs_search_query() {
    const BASE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scylla-wasm/web/mathlib.scylla"
    );

    // `scylla search --help` requests help for search command
    let (code, stdout, stderr) = run(&["search", "--help"]);
    assert_eq!(code, 0, "search --help should exit 0");
    assert!(
        stdout.contains("usage:"),
        "search --help should print usage"
    );
    assert!(stderr.is_empty(), "search --help stderr should be empty");

    // `scylla search <artifact> --help` treats --help as the search query
    let (code, stdout, stderr) = run(&["search", BASE, "--help"]);
    assert_eq!(code, 0, "search <artifact> --help is a valid search");
    assert!(stderr.is_empty(), "search query should not emit stderr");
    // searching for "--help" yields no matches (empty output)
    assert!(stdout.trim().is_empty());
}
