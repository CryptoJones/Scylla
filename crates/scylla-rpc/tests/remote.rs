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

/// Run the remote client against `addr` with `args` and an optional `SCYLLA_RPC_TOKEN`, returning
/// `(exit_code, stdout)`.
fn connect_with(addr: &str, args: &[&str], token: Option<&str>) -> (i32, String) {
    let mut full = vec![addr];
    full.extend_from_slice(args);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scylla-rpc-connect"));
    cmd.args(&full);
    match token {
        Some(t) => {
            cmd.env("SCYLLA_RPC_TOKEN", t);
        }
        None => {
            cmd.env_remove("SCYLLA_RPC_TOKEN");
        }
    }
    let out = cmd.output().expect("run scylla-rpc-connect");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Run the remote client with no token (the default; the server in the main test runs open).
fn connect(addr: &str, args: &[&str]) -> (i32, String) {
    connect_with(addr, args, None)
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

#[test]
fn token_gated_server_denies_without_the_token_over_tcp() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_RPC_TOKEN", "s3cret") // gate access (DD-035)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );

    // Ready when the RIGHT token logs in.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect_with(&addr, &["info"], Some("s3cret")).0 == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "token-gated server never came up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // No token / wrong token -> login denied (non-zero), and NO data leaks.
    let (no_tok, out_none) = connect_with(&addr, &["info"], None);
    assert_ne!(no_tok, 0, "no token must be denied");
    assert!(
        !out_none.contains("functions:"),
        "denied login must not leak data: {out_none}"
    );
    assert_ne!(
        connect_with(&addr, &["info"], Some("wrong")).0,
        0,
        "wrong token must be denied"
    );

    // The right token works.
    let (ok, out) = connect_with(&addr, &["info"], Some("s3cret"));
    assert_eq!(ok, 0, "the right token authenticates");
    assert!(out.contains("functions: 13"), "authed info: {out}");
}

#[test]
fn connection_cap_refuses_the_surplus_connection() {
    use std::net::TcpStream;
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_RPC_MAX_CONN", "1") // a single slot
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );

    // Ready (a normal client connects, completes, frees its slot).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "capped server never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Occupy the only slot with a raw, silent connection (held open), then the next client is over
    // the cap → its connection is dropped → login fails.
    let _hog = TcpStream::connect(&addr).expect("raw connect occupies the slot");
    std::thread::sleep(Duration::from_millis(500)); // let the server accept + count it
    let (code, _out) = connect(&addr, &["info"]);
    assert_ne!(code, 0, "a connection over the cap must be refused");

    // Free the slot; a client works again.
    drop(_hog);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "slot never freed after the hog dropped"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn handshake_timeout_frees_a_slot_from_a_silent_connection() {
    use std::net::TcpStream;
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_RPC_MAX_CONN", "1") // a single slot…
            .env("SCYLLA_RPC_HANDSHAKE_SEC", "1") // …dropped if not authed within 1s
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "server never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // A silent connection grabs the only slot but never logs in. WITHOUT a handshake timeout it would
    // squat the slot forever; WITH it, the server drops the silent connection after ~1s and a real
    // client succeeds — even though the test still holds the hog socket open.
    let _hog = TcpStream::connect(&addr).expect("raw connect occupies the slot");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut worked = false;
    while Instant::now() < deadline {
        if connect(&addr, &["info"]).0 == 0 {
            worked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        worked,
        "the silent connection must time out, freeing the slot for a real client"
    );
}
