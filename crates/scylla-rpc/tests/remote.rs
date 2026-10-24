//! End-to-end DD-002: spawn the REAL `scylla-rpc-serve` over TCP and drive it with the REAL
//! `scylla-rpc-connect` remote head — a consumer not co-located with the core, navigating the
//! client port over a Cap'n Proto RPC wire. Zero deps (std only).

mod common;

use std::ffi::OsStr;
use std::process::Command;
use std::time::{Duration, Instant};

const PATCHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_patched.scylla"
);

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
    let (_srv, addr) = common::spawn_server(&[]);

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
    // Gate access (DD-035).
    let (_srv, addr) = common::spawn_server(&[("SCYLLA_RPC_TOKEN", OsStr::new("s3cret"))]);

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
    use std::io::{ErrorKind, Read};
    use std::net::TcpStream;
    // A single slot.
    let (_srv, addr) = common::spawn_server(&[("SCYLLA_RPC_MAX_CONN", OsStr::new("1"))]);

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
    // the cap → its connection is dropped → login fails. The readiness client's slot is freed
    // asynchronously server-side, so the hog may arrive while that slot is still counted and be
    // refused itself. A refused hog reads EOF; one holding the slot reads nothing (the server waits
    // for its handshake). Retry until the hog holds the slot.
    let deadline = Instant::now() + Duration::from_secs(10);
    let _hog = loop {
        let mut hog = TcpStream::connect(&addr).expect("raw connect occupies the slot");
        hog.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        match hog.read(&mut [0u8; 1]) {
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break hog,
            _ => {}
        }
        assert!(Instant::now() < deadline, "the hog never held the slot");
        std::thread::sleep(Duration::from_millis(50));
    };
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
    // A single slot, dropped if not authed within 1s.
    let (_srv, addr) = common::spawn_server(&[
        ("SCYLLA_RPC_MAX_CONN", OsStr::new("1")),
        ("SCYLLA_RPC_HANDSHAKE_SEC", OsStr::new("1")),
    ]);
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

#[test]
fn whitespace_only_token_keeps_server_open() {
    // A blank/whitespace-only value is treated as unset (OPEN).
    let (_srv, addr) = common::spawn_server(&[("SCYLLA_RPC_TOKEN", OsStr::new("   \t  "))]);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect(&addr, &["info"]).0 == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "whitespace-token server never came up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Connect with no token succeeds because server treated whitespace token as OPEN
    let (code, out) = connect(&addr, &["info"]);
    assert_eq!(
        code, 0,
        "server with whitespace-only token must remain OPEN"
    );
    assert!(out.contains("functions: 13"), "remote info: {out}");
}
