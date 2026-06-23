//! Integration test for the HTTP/JSON gateway: spawn the REAL `scylla-http` binary and drive every
//! endpoint with a real HTTP client (ureq), asserting the JSON. Proves any HTTP consumer can read
//! the model — no WASM, no capnp.

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

    // unknown id → 404
    let err = ureq::get(&format!("{base}/api/functions/999999")).call();
    assert!(
        matches!(err, Err(ureq::Error::Status(404, _))),
        "unknown id should 404"
    );
}
