//! Contract-conformance for the MCP head (Sprint 9, DD-017/DD-022): same contract as the CLI / HTTP
//! / RPC heads, over MCP's JSON-RPC `tools/call`. The head is a 1:1 marshalling of the client port
//! (P6/DD-025: no domain logic), so a tool result must carry exactly what `scylla_port::Session`
//! computes for the same artifact — verb by verb, through the `<untrusted-data>` envelope (DD-035).
//! Expectations are derived from the port in-process; no frozen golden numbers (those live in the
//! lib's own unit tests). A head drifting from the body — or mis-marshalling it — fails here.

use scylla_mcp::dispatch;
use scylla_port::{Session, Zoom};
use serde_json::{json, Value};

const ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);
const PATCHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib_patched.scylla"
);

/// A session loaded the way the head's `main.rs` loads it — the source of truth for the contract.
fn port(path: &str) -> Session {
    Session::from_artifact(&std::fs::read(path).expect("read artifact")).expect("load artifact")
}

/// Drive one `tools/call` and return the response.
fn call(s: &mut Session, name: &str, args: Value) -> Value {
    dispatch(
        s,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": args}}),
    )
}

/// Pull the JSON payload out of a tool result, unwrapping the `<untrusted-data>` envelope when the
/// content is binary-derived (read tools wrap; status acks don't).
fn payload(resp: &Value) -> Value {
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a text content block: {resp}"));
    let inner = match text.split_once("<untrusted-data>\n") {
        Some((_, rest)) => rest
            .rsplit_once("\n</untrusted-data>")
            .map(|(p, _)| p)
            .unwrap_or(rest),
        None => text,
    };
    serde_json::from_str(inner).unwrap_or_else(|e| panic!("payload should be JSON: {e}\n{text}"))
}

#[test]
fn mcp_list_functions_matches_the_port() {
    let p = port(ARTIFACT);
    let mut head = port(ARTIFACT);
    let mut expected: Vec<String> = p
        .functions(Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();

    let resp = call(&mut head, "list_functions", json!({}));
    let mut got: Vec<String> = payload(&resp)
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();

    assert_eq!(got, expected, "list_functions == the port's functions");
}

#[test]
fn mcp_get_function_and_callers_match_the_port() {
    let p = port(ARTIFACT);
    let mut head = port(ARTIFACT);
    let gcd = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd present")
        .id;
    let pv = p.view(gcd, Zoom::Detail).expect("port view");

    // get_function (detail) — name + callers carried faithfully through the envelope.
    let resp = call(
        &mut head,
        "get_function",
        json!({"id": gcd.0, "zoom": "detail"}),
    );
    let v = payload(&resp);
    assert_eq!(v["name"], json!(pv.name), "get_function name");
    let got_callers: Vec<String> = v["callers"]
        .as_array()
        .expect("callers array")
        .iter()
        .map(|c| c.as_str().expect("caller").to_string())
        .collect();
    assert_eq!(
        got_callers,
        pv.callers.clone().unwrap_or_default(),
        "get_function callers == the port"
    );

    // callers tool — resolved caller names == the port's callers().
    let mut want: Vec<String> = p
        .callers(gcd)
        .into_iter()
        .map(|c| p.program().display_name(c).unwrap_or_default())
        .collect();
    want.sort();
    let resp = call(&mut head, "callers", json!({"id": gcd.0}));
    let mut got: Vec<String> = payload(&resp)
        .as_array()
        .expect("array")
        .iter()
        .map(|c| c["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();
    assert_eq!(got, want, "callers tool == the port");
}

#[test]
fn mcp_diff_matches_the_port() {
    let p = port(ARTIFACT);
    let mut head = port(ARTIFACT);
    let d = p.diff(&port(PATCHED));

    let resp = call(&mut head, "diff", json!({"artifact_path": PATCHED}));
    let v = payload(&resp);
    assert_eq!(
        v["matched"].as_u64().expect("matched number") as usize,
        d.matched.len(),
        "diff matched count == the port"
    );
    assert_eq!(
        v["modified"].as_array().expect("modified array").len(),
        d.changed.len(),
        "diff modified count == the port"
    );
    assert_eq!(
        v["only_in_session"]
            .as_array()
            .expect("only_in_session")
            .len(),
        d.only_here.len(),
        "diff only_in_session == the port"
    );
    assert_eq!(
        v["only_in_other"].as_array().expect("only_in_other").len(),
        d.only_there.len(),
        "diff only_in_other == the port"
    );
    // The match-confidence breakdown is carried through too (DD-017 provenance).
    let methods = v["methods"].as_object().expect("a methods object");
    let total: u64 = methods.values().filter_map(serde_json::Value::as_u64).sum();
    assert_eq!(
        total as usize,
        d.matched.len() + d.changed.len(),
        "methods account for every matched/changed pair"
    );
    // …and per-pair confidence: one entry per matched/changed pair, each {method, confidence}.
    let confidence = v["confidence"].as_object().expect("a confidence object");
    assert_eq!(
        confidence.len(),
        d.matched.len() + d.changed.len(),
        "one confidence entry per pair"
    );
    for entry in confidence.values() {
        assert!(entry["method"].is_string(), "each entry names a method");
        assert!(entry["confidence"].is_u64(), "each entry has a confidence %");
    }
}

#[test]
fn mcp_search_matches_the_port() {
    let p = port(ARTIFACT);
    let mut head = port(ARTIFACT);
    let mut expected: Vec<String> = p
        .search("gc", Zoom::Domain)
        .into_iter()
        .map(|f| f.name)
        .collect();
    expected.sort();

    let resp = call(&mut head, "search", json!({"query": "gc"}));
    let mut got: Vec<String> = payload(&resp)
        .as_array()
        .expect("array")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();

    assert_eq!(got, expected, "the search tool == the port's search");
    assert_eq!(got, vec!["gcd".to_string()], "narrows to gcd (case-insensitive)");
}
