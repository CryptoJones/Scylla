//! Contract-conformance for the GraphQL head (DD-017): the same contract the CLI and HTTP heads'
//! `conformance.rs` enforce, over GraphQL. The graph is a thin projection of the client port, so its
//! query results must equal what `scylla_port::Session` computes for the same artifact — verb by
//! verb. Expectations are derived from the port in-process; no frozen golden numbers. If the head
//! drifts from the body, these fail.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use scylla_port::{Session, Zoom};

const ARTIFACT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/mathlib.scylla");
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
fn graphql_head_conforms_to_the_port() {
    let p = port(ARTIFACT);
    let prog = p.program();

    let port_num = free_port();
    let addr = format!("127.0.0.1:{port_num}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-graphql"))
            .args([ARTIFACT, &addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-graphql"),
    );

    // Wait until it's serving.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/")).call().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-graphql never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Execute a GraphQL query, assert it carried no `errors`, and hand back the `data` object.
    let gql = |query: &str| -> serde_json::Value {
        let req = serde_json::json!({ "query": query }).to_string();
        let body = ureq::post(&format!("{base}/graphql"))
            .set("Content-Type", "application/json")
            .send_string(&req)
            .unwrap_or_else(|e| panic!("POST graphql ({query}): {e}"))
            .into_string()
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse ({query}): {e}\n{body}"));
        assert!(
            v.get("errors").is_none(),
            "graphql errors for ({query}): {body}"
        );
        v["data"].clone()
    };

    // info — function count matches the port.
    let info = gql("{ info { functions } }");
    assert_eq!(
        info["info"]["functions"].as_i64().expect("functions number") as usize,
        prog.functions.len(),
        "info function count matches the port"
    );

    // functions — the listed name set matches the port's.
    let mut expected: Vec<String> = p.functions(Zoom::Domain).into_iter().map(|f| f.name).collect();
    expected.sort();
    let d = gql("{ functions { name } }");
    let mut got: Vec<String> = d["functions"]
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();
    assert_eq!(got, expected, "the graph lists exactly the port's functions");

    // function — gcd's name + callers match the port at DETAIL zoom.
    let gid = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd present")
        .id;
    let pv = p.view(gid, Zoom::Detail).expect("port view");
    let d = gql(&format!(
        "{{ function(id: \"{}\", zoom: DETAIL) {{ name callers }} }}",
        gid.0
    ));
    assert_eq!(
        d["function"]["name"].as_str().expect("name"),
        pv.name,
        "view name"
    );
    let got_callers: Vec<String> = d["function"]["callers"]
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
    let dp = p.diff(&port(PATCHED));
    let renamed = dp.matched.iter().filter(|(x, y)| x != y).count();
    let unchanged = dp.matched.len() - renamed;
    let patched_b64 = B64.encode(std::fs::read(PATCHED).unwrap());
    let d = gql(&format!(
        "{{ diff(artifactBase64: \"{patched_b64}\") {{ matched modified {{ from }} added removed }} }}"
    ));
    assert_eq!(
        d["diff"]["matched"].as_i64().expect("matched number") as usize,
        unchanged,
        "diff unchanged count matches the port"
    );
    assert_eq!(
        d["diff"]["modified"].as_array().expect("modified").len(),
        dp.changed.len(),
        "diff modified count matches the port"
    );
    assert_eq!(
        d["diff"]["added"].as_array().expect("added").len(),
        dp.only_there.len(),
        "diff added count matches the port"
    );
    assert_eq!(
        d["diff"]["removed"].as_array().expect("removed").len(),
        dp.only_here.len(),
        "diff removed count matches the port"
    );
}
