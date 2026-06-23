//! Contract-conformance for the HTTP/JSON gateway head (Sprint 9, DD-017): same contract as the CLI
//! head's `conformance.rs`, over HTTP. The gateway is a thin projection of the client port, so its
//! JSON responses must equal what `scylla_port::Session` computes for the same artifact — verb by
//! verb. Expectations are derived from the port in-process; no frozen golden numbers (those live in
//! `api.rs`). If the head drifts from the body, these fail.

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

/// The port, loaded the same way the head loads it — the source of truth for the contract.
fn port(path: &str) -> Session {
    Session::from_artifact(&std::fs::read(path).expect("read artifact")).expect("load artifact")
}

#[test]
fn http_gateway_conforms_to_the_port() {
    let p = port(ARTIFACT);
    let prog = p.program();

    let port_num = free_port();
    let addr = format!("127.0.0.1:{port_num}");
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

    let get = |path: &str| -> serde_json::Value {
        let body = ureq::get(&format!("{base}{path}"))
            .call()
            .unwrap_or_else(|e| panic!("GET {path}: {e}"))
            .into_string()
            .unwrap();
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("GET {path} JSON: {e}\n{body}"))
    };

    // info — function count matches the port.
    let info = get("/api/info");
    assert_eq!(
        info["functions"].as_u64().expect("functions number") as usize,
        prog.functions.len(),
        "info function count matches the port"
    );

    // functions — the listed name set matches the port's.
    let mut expected: Vec<String> = p
        .functions(Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();
    let fns = get("/api/functions");
    let mut got: Vec<String> = fns
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();
    assert_eq!(
        got, expected,
        "the gateway lists exactly the port's functions"
    );

    // view — gcd's name + callers match the port.
    let gid = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd present")
        .id;
    let pv = p.view(gid, Zoom::Detail).expect("port view");
    let v = get(&format!("/api/functions/{}?zoom=detail", gid.0));
    assert_eq!(v["name"], serde_json::json!(pv.name), "view name");
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

    // diff — counts match the port's diff() against the patched build.
    let d = p.diff(&port(PATCHED));
    let renamed = d.matched.iter().filter(|(x, y)| x != y).count();
    let unchanged = d.matched.len() - renamed;
    let patched = std::fs::read(PATCHED).unwrap();
    let body = ureq::post(&format!("{base}/api/diff"))
        .send_bytes(&patched)
        .unwrap()
        .into_string()
        .unwrap();
    let diff: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        diff["matched"].as_u64().expect("matched number") as usize,
        unchanged,
        "diff unchanged count matches the port"
    );
    assert_eq!(
        diff["modified"].as_array().expect("modified array").len(),
        d.changed.len(),
        "diff modified count matches the port"
    );
    assert_eq!(
        diff["added"].as_array().expect("added array").len(),
        d.only_there.len(),
        "diff added count matches the port"
    );
    assert_eq!(
        diff["removed"].as_array().expect("removed array").len(),
        d.only_here.len(),
        "diff removed count matches the port"
    );
}
