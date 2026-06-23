//! Behaviour tests for the GraphQL head that the conformance suite doesn't cover: token gating
//! (DD-035), the annotation WRITE path round-tripping into a subsequent read (DD-005), schema
//! introspection, and fail-closed error surfacing (a rejected mutation is a GraphQL `errors`, not a
//! silent `ok: false`).

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use scylla_port::{Session, Zoom};

const ARTIFACT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/mathlib.scylla");

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
fn token_gates_and_the_write_path_round_trips() {
    let port_num = free_port();
    let addr = format!("127.0.0.1:{port_num}");
    let base = format!("http://{addr}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-graphql"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_GRAPHQL_TOKEN", "secret")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-graphql"),
    );

    // Wait until serving — readiness probe must carry the bearer, since every request is gated.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if ureq::get(&format!("{base}/"))
            .set("Authorization", "Bearer secret")
            .call()
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "scylla-graphql never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Unauthorized: no bearer → rejected (ureq surfaces the 401 as an Err).
    let unauth = ureq::post(&format!("{base}/graphql"))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"query": "{ info { name } }"}).to_string());
    assert!(unauth.is_err(), "an unauthenticated query must be rejected");

    // Authorized GraphQL — returns the full {data, errors?} envelope.
    let gql = |query: &str| -> serde_json::Value {
        let req = serde_json::json!({ "query": query }).to_string();
        let body = ureq::post(&format!("{base}/graphql"))
            .set("Authorization", "Bearer secret")
            .set("Content-Type", "application/json")
            .send_string(&req)
            .unwrap_or_else(|e| panic!("POST graphql ({query}): {e}"))
            .into_string()
            .unwrap();
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse ({query}): {e}\n{body}"))
    };

    // Introspection works — the schema is self-describing.
    let intro = gql("{ __schema { queryType { name } mutationType { name } } }");
    assert_eq!(
        intro["data"]["__schema"]["queryType"]["name"]
            .as_str()
            .expect("queryType name"),
        "Query"
    );
    assert_eq!(
        intro["data"]["__schema"]["mutationType"]["name"]
            .as_str()
            .expect("mutationType name"),
        "Mutation"
    );

    // The write path: rename gcd, then read it back — the durable fact is visible (DD-005).
    let gid = Session::from_artifact(&std::fs::read(ARTIFACT).unwrap())
        .unwrap()
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd present")
        .id;

    let renamed = gql(&format!(
        "mutation {{ rename(id: \"{}\", name: \"my_gcd\") {{ ok id }} }}",
        gid.0
    ));
    assert_eq!(
        renamed["data"]["rename"]["ok"].as_bool(),
        Some(true),
        "rename acknowledged"
    );

    let view = gql(&format!("{{ function(id: \"{}\") {{ name }} }}", gid.0));
    assert_eq!(
        view["data"]["function"]["name"].as_str().expect("name"),
        "my_gcd",
        "the rename is visible on the next read"
    );

    // Export reflects the annotated model — a non-empty base64 .scylla.
    let exported = gql("{ export }");
    assert!(
        !exported["data"]["export"]
            .as_str()
            .expect("export string")
            .is_empty(),
        "export returns the annotated artifact"
    );

    // Fail-closed: a blank rename is a GraphQL error, not a silent success.
    let blank = gql(&format!(
        "mutation {{ rename(id: \"{}\", name: \"\") {{ ok }} }}",
        gid.0
    ));
    assert!(
        blank.get("errors").is_some(),
        "a blank rename must surface as a GraphQL error"
    );
}
