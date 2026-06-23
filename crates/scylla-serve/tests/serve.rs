//! Integration tests for `scylla-serve`: spawn the REAL binary (`CARGO_BIN_EXE_scylla-serve`) on an
//! ephemeral port and exercise every route over raw HTTP/1.1 — so arg parsing + serving are
//! CI-protected, not just hand-smoke-tested. Zero deps (std only), matching the crate.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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

/// Ask the OS for a free port, then drop the listener so the child can bind it. (Tiny race window;
/// fine for a test — if the child loses the race it exits and `wait_ready` fails fast.)
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One raw HTTP/1.1 `GET` (Connection: close) → `(status_line, header_block, body_bytes)`.
fn get(port: u16, path: &str) -> (String, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
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

/// A spawned server that is killed on drop.
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(args: &[&str]) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_scylla-serve"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn scylla-serve");
    Server(child)
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("scylla-serve did not become ready on port {port}");
}

#[test]
fn serves_head_artifact_and_compare() {
    let port = free_port();
    let _srv = spawn(&[BASE, COMPARE, &port.to_string()]);
    wait_ready(port);

    let base = std::fs::read(BASE).unwrap();
    let compare = std::fs::read(COMPARE).unwrap();

    // the head itself
    let (status, head, body) = get(port, "/");
    assert!(status.contains("200"), "GET / → {status}");
    assert!(head.contains("text/html"), "GET / content-type: {head}");
    assert!(String::from_utf8_lossy(&body).contains("Scylla — WASM head"));

    // the wasm module (magic bytes \0asm)
    let (status, head, body) = get(port, "/scylla_wasm.wasm");
    assert!(status.contains("200"));
    assert!(head.contains("application/wasm"));
    assert!(body.len() >= 4 && &body[..4] == b"\0asm", "wasm magic");

    // the base artifact, exact bytes, where the head fetches it
    let (status, _h, body) = get(port, "/mathlib.scylla");
    assert!(status.contains("200"));
    assert_eq!(body, base, "base artifact bytes");

    // the compare build, exact bytes
    let (status, _h, body) = get(port, "/compare.scylla");
    assert!(status.contains("200"));
    assert_eq!(body, compare, "compare artifact bytes");

    // anything else
    let (status, _h, _b) = get(port, "/nope");
    assert!(status.contains("404"), "GET /nope → {status}");
}

#[test]
fn compare_404s_without_a_second_artifact() {
    let port = free_port();
    let _srv = spawn(&[BASE, &port.to_string()]);
    wait_ready(port);

    let (status, _h, _b) = get(port, "/compare.scylla");
    assert!(
        status.contains("404"),
        "single-artifact /compare.scylla → {status}"
    );
    // sanity: the base artifact is still served in single-artifact mode
    let (s2, _h, _b) = get(port, "/mathlib.scylla");
    assert!(s2.contains("200"));
}
