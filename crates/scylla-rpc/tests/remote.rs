//! End-to-end DD-002: spawn the REAL `scylla-rpc-serve` over TCP and drive it with the REAL
//! `scylla-rpc-connect` remote head — a consumer not co-located with the core, navigating the
//! client port over a Cap'n Proto RPC wire. Zero deps (std only).

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

/// A spawned server, killed on drop.
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run the remote client against `addr` with `args`, returning `(exit_code, stdout)`.
fn connect(addr: &str, args: &[&str]) -> (i32, String) {
    let mut full = vec![addr];
    full.extend_from_slice(args);
    let out = Command::new(env!("CARGO_BIN_EXE_scylla-rpc-connect"))
        .args(&full)
        .output()
        .expect("run scylla-rpc-connect");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn remote_head_drives_the_port_over_tcp() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );

    // Wait until the server is accepting (the client `info` round-trips cleanly).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "scylla-rpc-serve never came up on {addr}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // info — the artifact metadata, over the wire.
    let (code, out) = connect(&addr, &["info"]);
    assert_eq!(code, 0, "remote info exit 0");
    assert!(out.contains("functions: 13"), "remote info: {out}");

    // functions — one capability per function; find gcd's stable id.
    let (code, out) = connect(&addr, &["functions"]);
    assert_eq!(code, 0);
    let gid = out
        .lines()
        .find(|l| l.split('\t').nth(1) == Some("gcd"))
        .and_then(|l| l.split('\t').next())
        .expect("gcd is listed over the wire")
        .to_string();

    // callers — PIPELINED `function(gcd).callers().view()`, reproduced remotely.
    let (code, out) = connect(&addr, &["callers", gid.as_str()]);
    assert_eq!(code, 0);
    assert!(
        out.contains("main"),
        "gcd's remote callers should include main: {out}"
    );

    // diff — the full structural diff runs server-side, the report comes back over the wire.
    let (code, out) = connect(&addr, &["diff", PATCHED]);
    assert_eq!(code, 0, "remote diff exit 0");
    assert!(out.contains("1 modified"), "remote diff summary: {out}");
    assert!(
        out.contains("modified: gcd"),
        "gcd reported modified over the wire: {out}"
    );

    // a non-integer id is a clean failure, not a panic
    let (code, _out) = connect(&addr, &["view", "not-a-number"]);
    assert_ne!(code, 0, "a bad id fails cleanly");
}
