//! Contract-conformance for the remote RPC head (Sprint 9, DD-017/DD-002): same contract as the CLI
//! and HTTP heads, over the Cap'n Proto wire. Spawn the real `scylla-rpc-serve`, drive it with the
//! real `scylla-rpc-connect`, and assert its output equals what `scylla_port::Session` computes for
//! the same artifact — verb by verb. Expectations are derived from the port in-process; no frozen
//! golden numbers (those live in `remote.rs`). A head drifting from the body fails here.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use scylla_port::{Session, Zoom};

const ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);
const PATCHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_patched.scylla"
);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run the remote client (no token — the server runs open here), returning `(exit, stdout)`.
fn connect(addr: &str, args: &[&str]) -> (i32, String) {
    let mut full = vec![addr];
    full.extend_from_slice(args);
    let out = Command::new(env!("CARGO_BIN_EXE_scylla-rpc-connect"))
        .args(&full)
        .env_remove("SCYLLA_RPC_TOKEN")
        .output()
        .expect("run scylla-rpc-connect");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The port, loaded the same way the head loads it — the source of truth for the contract.
fn port(path: &str) -> Session {
    Session::from_artifact(&std::fs::read(path).expect("read artifact")).expect("load artifact")
}

/// The integer that follows `label:` in a `label: value` line (e.g. `functions: 13`).
fn field_num(out: &str, label: &str) -> u64 {
    out.lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == label))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no `{label}:` numeric line in:\n{out}"))
}

/// The count before `word` in the diff summary `N unchanged · N renamed · …`.
fn summary_count(summary: &str, word: &str) -> usize {
    summary
        .split('·')
        .find_map(|seg| {
            let mut it = seg.split_whitespace();
            let n: usize = it.next()?.parse().ok()?;
            (it.next()? == word).then_some(n)
        })
        .unwrap_or_else(|| panic!("no `{word}` in diff summary: {summary:?}"))
}

#[test]
fn rpc_head_conforms_to_the_port() {
    let p = port(ARTIFACT);
    let prog = p.program();

    let pnum = free_port();
    let addr = format!("127.0.0.1:{pnum}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );

    // Wait until the server accepts (info round-trips).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-rpc-serve never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // info — function count matches the port.
    let (code, out) = connect(&addr, &["info"]);
    assert_eq!(code, 0, "info exit 0");
    assert_eq!(
        field_num(&out, "functions") as usize,
        prog.functions.len(),
        "remote function count matches the port"
    );

    // functions — the listed name set matches the port's.
    let mut expected: Vec<String> = p
        .functions(Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();
    let (code, out) = connect(&addr, &["functions"]);
    assert_eq!(code, 0);
    let mut got: Vec<String> = out
        .lines()
        .filter_map(|l| l.split('\t').nth(1).map(str::to_string))
        .collect();
    got.sort();
    assert_eq!(got, expected, "the remote head lists the port's functions");

    // gcd's id, resolved over the wire (robust to re-mint).
    let gid = out
        .lines()
        .find(|l| l.split('\t').nth(1) == Some("gcd"))
        .and_then(|l| l.split('\t').next())
        .expect("gcd listed")
        .to_string();
    let gcd_id = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd in port")
        .id;

    // view — name + blocks match the port's view(detail).
    let pv = p.view(gcd_id, Zoom::Detail).expect("port view");
    let (code, out) = connect(&addr, &["view", &gid, "detail"]);
    assert_eq!(code, 0, "view exit 0");
    assert!(
        out.lines()
            .any(|l| l.trim() == format!("name:    {}", pv.name)),
        "remote view names {}: {out}",
        pv.name
    );
    assert_eq!(
        field_num(&out, "blocks"),
        pv.bb_count.expect("detail bb_count") as u64,
        "remote view blocks match the port"
    );

    // callers — the resolved caller names match the port's.
    let mut want_callers: Vec<String> = p
        .callers(gcd_id)
        .into_iter()
        .map(|c| prog.display_name(c).unwrap_or_default())
        .collect();
    want_callers.sort();
    let (code, out) = connect(&addr, &["callers", &gid]);
    assert_eq!(code, 0, "callers exit 0");
    let mut got: Vec<String> = out
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect();
    got.sort();
    assert_eq!(got, want_callers, "remote callers match the port");

    // diff — the summary counts match the port's diff() against the patched build.
    let d = p.diff(&port(PATCHED));
    let renamed = d.matched.iter().filter(|(x, y)| x != y).count();
    let unchanged = d.matched.len() - renamed;
    let (code, out) = connect(&addr, &["diff", PATCHED]);
    assert_eq!(code, 0, "diff exit 0");
    let summary = out.lines().next().expect("a diff summary line");
    assert_eq!(summary_count(summary, "unchanged"), unchanged, "unchanged");
    assert_eq!(summary_count(summary, "renamed"), renamed, "renamed");
    assert_eq!(
        summary_count(summary, "modified"),
        d.changed.len(),
        "modified"
    );
    assert_eq!(summary_count(summary, "added"), d.only_there.len(), "added");
    assert_eq!(
        summary_count(summary, "removed"),
        d.only_here.len(),
        "removed"
    );
    // the match-confidence breakdown comes over the wire too (DD-017 provenance).
    assert!(
        out.lines().any(|l| l.starts_with("matched by:")),
        "remote diff reports a confidence breakdown: {out}"
    );
    // …and each modified line is annotated with its per-pair rung + confidence %.
    assert!(
        out.lines()
            .any(|l| l.starts_with("modified:") && l.contains("%)")),
        "remote modified lines carry per-pair confidence: {out}"
    );

    // export — the connect binary pulls the served model down to a .scylla that reloads with the
    // same functions as the port (the new `export` verb, end-to-end over the wire).
    let outp =
        std::env::temp_dir().join(format!("scylla-rpc-export-{}.scylla", std::process::id()));
    let (code, _) = connect(&addr, &["export", outp.to_str().unwrap()]);
    assert_eq!(code, 0, "export exit 0");
    let mut got: Vec<String> = port(outp.to_str().unwrap())
        .functions(Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    got.sort();
    assert_eq!(
        got, expected,
        "the exported artifact reloads with the port's functions"
    );
    let _ = std::fs::remove_file(&outp);
}
