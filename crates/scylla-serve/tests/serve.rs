//! Integration tests for `scylla-serve`: spawn the REAL binary (`CARGO_BIN_EXE_scylla-serve`) on an
//! ephemeral port and exercise every route over raw HTTP/1.1 — so arg parsing + serving are
//! CI-protected, not just hand-smoke-tested. Zero deps (std only), matching the crate.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

// The committed sample artifacts (this crate's manifest dir is crates/scylla-serve).
const BASE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);
const COMPARE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_rebuilt.scylla"
);

/// One raw HTTP/1.1 `GET` (Connection: close) → `(status_line, header_block, body_bytes)`.
fn get(addr: &str, path: &str) -> (String, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap(); // server sets Connection: close, so this terminates
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header/body separator");
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let body = buf[split + 4..].to_vec();
    let status = head.lines().next().unwrap_or_default().to_string();
    (status, head, body)
}

fn wait_ready(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("scylla-serve did not become ready on {addr}");
}

#[test]
fn serves_head_artifact_and_compare() {
    let (_srv, addr) = common::spawn_server(&[BASE, COMPARE]);
    wait_ready(&addr);

    let base = std::fs::read(BASE).unwrap();
    let compare = std::fs::read(COMPARE).unwrap();

    // the head itself
    let (status, head, body) = get(&addr, "/");
    assert!(status.contains("200"), "GET / → {status}");
    assert!(head.contains("text/html"), "GET / content-type: {head}");
    assert!(String::from_utf8_lossy(&body).contains("Scylla — WASM head"));

    // the wasm module (magic bytes \0asm)
    let (status, head, body) = get(&addr, "/scylla_wasm.wasm");
    assert!(status.contains("200"));
    assert!(head.contains("application/wasm"));
    assert!(body.len() >= 4 && &body[..4] == b"\0asm", "wasm magic");

    // the base artifact, exact bytes, where the head fetches it
    let (status, _h, body) = get(&addr, "/mathlib.scylla");
    assert!(status.contains("200"));
    assert_eq!(body, base, "base artifact bytes");

    // the compare build, exact bytes
    let (status, _h, body) = get(&addr, "/compare.scylla");
    assert!(status.contains("200"));
    assert_eq!(body, compare, "compare artifact bytes");

    // anything else
    let (status, _h, _b) = get(&addr, "/nope");
    assert!(status.contains("404"), "GET /nope → {status}");
}

#[test]
fn compare_404s_without_a_second_artifact() {
    let (_srv, addr) = common::spawn_server(&[BASE]);
    wait_ready(&addr);

    let (status, _h, _b) = get(&addr, "/compare.scylla");
    assert!(
        status.contains("404"),
        "single-artifact /compare.scylla → {status}"
    );
    // sanity: the base artifact is still served in single-artifact mode
    let (s2, _h, _b) = get(&addr, "/mathlib.scylla");
    assert!(s2.contains("200"));
}
