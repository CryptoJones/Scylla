//! Integration test for the HTTP/JSON gateway: spawn the REAL `scylla-http` binary and drive every
//! endpoint with a real HTTP client (ureq), asserting the JSON. Proves any HTTP consumer can read
//! the model — no WASM, no capnp.

use std::io::Read;
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

#[test]
fn http_gateway_serves_the_model_as_json() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-http"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-http"),
    );

    // Wait until it's serving.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/api/info")).call().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-http never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // info
    let info = ureq::get(&format!("{base}/api/info"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(info.contains("\"functions\":13"), "info: {info}");

    // functions → find gcd's id
    let fns_body = ureq::get(&format!("{base}/api/functions"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    let fns: serde_json::Value = serde_json::from_str(&fns_body).unwrap();
    let gid = fns
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "gcd")
        .expect("gcd listed")["id"]
        .as_u64()
        .unwrap();

    // view (detail) — addr + callers come back
    let view = ureq::get(&format!("{base}/api/functions/{gid}?zoom=detail"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(view.contains("\"name\":\"gcd\""), "view: {view}");
    assert!(
        view.contains("\"callers\":[\"main\"]"),
        "gcd called by main: {view}"
    );

    // callers
    let callers = ureq::get(&format!("{base}/api/functions/{gid}/callers"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(callers.contains("main"), "callers: {callers}");

    // POST diff vs the patched build → gcd modified
    let patched = std::fs::read(PATCHED).unwrap();
    let diff = ureq::post(&format!("{base}/api/diff"))
        .send_bytes(&patched)
        .unwrap()
        .into_string()
        .unwrap();
    assert!(diff.contains("\"matched\":12"), "diff: {diff}");
    assert!(diff.contains("gcd"), "diff names gcd: {diff}");
    assert!(
        diff.contains("\"methods\""),
        "diff has a methods breakdown: {diff}"
    );
    assert!(
        diff.contains("\"confidence\""),
        "diff has per-pair confidence: {diff}"
    );

    // unknown id → 404
    let err = ureq::get(&format!("{base}/api/functions/999999")).call();
    assert!(
        matches!(err, Err(ureq::Error::Status(404, _))),
        "unknown id should 404"
    );
}

#[test]
fn http_gateway_annotates_the_resident_session() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-http"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-http"),
    );

    // Wait until it's serving.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/api/info")).call().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-http never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Find gcd's id.
    let fns_body = ureq::get(&format!("{base}/api/functions"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    let fns: serde_json::Value = serde_json::from_str(&fns_body).unwrap();
    let gid = fns
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "gcd")
        .expect("gcd listed")["id"]
        .as_u64()
        .unwrap();

    // rename — POST mutates the resident session; the next read reflects it (DD-005).
    let resp = ureq::post(&format!("{base}/api/functions/{gid}/rename"))
        .send_string(r#"{"name": "euclid_gcd"}"#)
        .unwrap()
        .into_string()
        .unwrap();
    assert!(resp.contains("\"ok\":true"), "rename ok: {resp}");
    let v = ureq::get(&format!("{base}/api/functions/{gid}?zoom=detail"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(v.contains("\"name\":\"euclid_gcd\""), "renamed view: {v}");

    // comment + retype show up in the view (read straight off the facts).
    ureq::post(&format!("{base}/api/functions/{gid}/comment"))
        .send_string(r#"{"text": "Euclid's algorithm"}"#)
        .unwrap();
    ureq::post(&format!("{base}/api/functions/{gid}/retype"))
        .send_string(r#"{"type": "u64(u64,u64)"}"#)
        .unwrap();
    let v = ureq::get(&format!("{base}/api/functions/{gid}?zoom=detail"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(
        v.contains("\"comment\":\"Euclid's algorithm\""),
        "comment in view: {v}"
    );
    assert!(v.contains("\"type\":\"u64(u64,u64)\""), "type in view: {v}");

    // A blank rename is rejected (port invariant) → 400, and the name is unchanged.
    let blank =
        ureq::post(&format!("{base}/api/functions/{gid}/rename")).send_string(r#"{"name": ""}"#);
    assert!(
        matches!(blank, Err(ureq::Error::Status(400, _))),
        "blank rename must be 400"
    );

    // Annotating an unknown id → 404.
    let missing =
        ureq::post(&format!("{base}/api/functions/999999/rename")).send_string(r#"{"name": "x"}"#);
    assert!(
        matches!(missing, Err(ureq::Error::Status(404, _))),
        "unknown id must be 404"
    );
}

#[test]
fn http_gateway_exports_the_annotated_model() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-http"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-http"),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/api/info")).call().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-http never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Find gcd, rename it in the resident session.
    let fns_body = ureq::get(&format!("{base}/api/functions"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    let fns: serde_json::Value = serde_json::from_str(&fns_body).unwrap();
    let gid = fns
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "gcd")
        .expect("gcd listed")["id"]
        .as_u64()
        .unwrap();
    ureq::post(&format!("{base}/api/functions/{gid}/rename"))
        .send_string(r#"{"name": "euclid_gcd"}"#)
        .unwrap();

    // Export the model and reload it — the annotation persisted across the artifact round-trip.
    let resp = ureq::get(&format!("{base}/api/export")).call().unwrap();
    assert_eq!(
        resp.header("Content-Type"),
        Some("application/octet-stream"),
        "export is binary, not JSON"
    );
    let mut bytes = Vec::new();
    resp.into_reader().read_to_end(&mut bytes).unwrap();
    let reloaded = Session::from_artifact(&bytes).expect("exported bytes are a valid .scylla");
    assert!(
        reloaded
            .functions(Zoom::Domain)
            .iter()
            .any(|f| f.name == "euclid_gcd"),
        "the rename survived export → reload"
    );
}

#[test]
fn http_gateway_token_gates_access() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-http"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_HTTP_TOKEN", "s3cret") // gate access (DD-035)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-http"),
    );

    // Ready when the RIGHT token is accepted.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/api/info"))
            .set("Authorization", "Bearer s3cret")
            .call()
            .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "token-gated gateway never came up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // No token / wrong token → 401 (and no data).
    let no_tok = ureq::get(&format!("{base}/api/info")).call();
    assert!(
        matches!(no_tok, Err(ureq::Error::Status(401, _))),
        "no token must be 401"
    );
    let wrong = ureq::get(&format!("{base}/api/info"))
        .set("Authorization", "Bearer nope")
        .call();
    assert!(
        matches!(wrong, Err(ureq::Error::Status(401, _))),
        "wrong token must be 401"
    );

    // Right token works.
    let info = ureq::get(&format!("{base}/api/info"))
        .set("Authorization", "Bearer s3cret")
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(info.contains("\"functions\":13"), "authed info: {info}");
}
