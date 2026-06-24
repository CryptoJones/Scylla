//! Contract-conformance for the LSP head (DD-017): same contract as the CLI / HTTP / GraphQL / MCP /
//! TUI heads, over LSP. The server is a thin projection of the client port, so each LSP reply must
//! equal what `scylla_port::Session` computes for the same artifact — documentSymbol == `functions`,
//! hover == `view`, references == `callers`, workspace/symbol == `search`, rename == the annotate
//! verb. Driven in-process through `dispatch` (no editor, no pipe); expectations derived from the
//! port; no golden numbers.

use scylla_lsp::dispatch;
use scylla_port::{Session, Zoom};
use serde_json::{json, Value};

const ARTIFACT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scylla-wasm/web/mathlib.scylla");

fn load() -> Session {
    Session::from_artifact(&std::fs::read(ARTIFACT).expect("read artifact")).expect("load artifact")
}

fn rq(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

fn symbols(s: &mut Session) -> Vec<Value> {
    let resp = dispatch(
        s,
        &rq(
            "textDocument/documentSymbol",
            json!({"textDocument": {"uri": "scylla:program"}}),
        ),
    )
    .expect("response");
    resp["result"].as_array().expect("symbol array").clone()
}

/// The 0-based listing line of a function by name (the position editors send for hover/refs/rename).
fn line_of(s: &mut Session, name: &str) -> usize {
    symbols(s)
        .iter()
        .position(|x| x["name"] == json!(name))
        .unwrap_or_else(|| panic!("{name} present in document symbols"))
}

#[test]
fn document_symbols_are_the_ports_functions_in_address_order() {
    let mut s = load();
    let got: Vec<String> = symbols(&mut s)
        .iter()
        .map(|x| x["name"].as_str().expect("name").to_string())
        .collect();

    let p = load();
    let mut fns = p.functions(Zoom::Domain);
    fns.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.name.cmp(&b.name)));
    let expected: Vec<String> = fns.into_iter().map(|f| f.name).collect();

    assert_eq!(got, expected, "documentSymbol is the port's functions, address-ordered");
}

#[test]
fn hover_is_the_ports_view_and_is_untrusted_wrapped() {
    let mut s = load();
    let line = line_of(&mut s, "gcd");
    let resp = dispatch(
        &mut s,
        &rq(
            "textDocument/hover",
            json!({"textDocument": {"uri": "scylla:program"}, "position": {"line": line, "character": 0}}),
        ),
    )
    .expect("response");
    let md = resp["result"]["contents"]["value"].as_str().expect("hover markdown");
    assert!(md.contains("gcd"), "hover names the function");
    assert!(
        md.contains("<untrusted-data>"),
        "hover wraps binary-derived text (DD-035)"
    );
}

#[test]
fn references_are_the_ports_callers() {
    let mut s = load();
    let p = load();
    let gid = p
        .functions(Zoom::Domain)
        .into_iter()
        .find(|f| f.name == "gcd")
        .expect("gcd")
        .id;
    let expected = p.callers(gid).len();

    let line = line_of(&mut s, "gcd");
    let resp = dispatch(
        &mut s,
        &rq(
            "textDocument/references",
            json!({"textDocument": {"uri": "scylla:program"}, "position": {"line": line, "character": 0}, "context": {"includeDeclaration": false}}),
        ),
    )
    .expect("response");
    assert_eq!(
        resp["result"].as_array().expect("locations").len(),
        expected,
        "references == the port's callers count"
    );
}

#[test]
fn workspace_symbol_is_the_ports_search() {
    let mut s = load();
    let resp = dispatch(&mut s, &rq("workspace/symbol", json!({"query": "gc"}))).expect("response");
    let mut got: Vec<String> = resp["result"]
        .as_array()
        .expect("symbol array")
        .iter()
        .map(|x| x["name"].as_str().expect("name").to_string())
        .collect();
    got.sort();

    let p = load();
    let mut expected: Vec<String> = p.search("gc", Zoom::Domain).into_iter().map(|f| f.name).collect();
    expected.sort();

    assert_eq!(got, expected, "workspace/symbol == the port's search()");
}

#[test]
fn rename_returns_a_workspace_edit_and_round_trips() {
    let mut s = load();
    let line = line_of(&mut s, "gcd");
    let resp = dispatch(
        &mut s,
        &rq(
            "textDocument/rename",
            json!({"textDocument": {"uri": "scylla:program"}, "position": {"line": line, "character": 0}, "newName": "my_gcd"}),
        ),
    )
    .expect("response");
    assert!(
        resp["result"]["changes"]["scylla:program"].is_array(),
        "rename returns a WorkspaceEdit for the virtual document"
    );

    // The rename is durable — the next documentSymbol shows the new name, the old is gone.
    let names: Vec<String> = symbols(&mut s)
        .iter()
        .map(|x| x["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"my_gcd".to_string()), "rename is visible on the next read");
    assert!(!names.contains(&"gcd".to_string()), "the old name is gone");
}

#[test]
fn initialize_advertises_the_capabilities() {
    let mut s = load();
    let resp = dispatch(&mut s, &rq("initialize", json!({}))).expect("response");
    let caps = &resp["result"]["capabilities"];
    for c in [
        "documentSymbolProvider",
        "hoverProvider",
        "referencesProvider",
        "renameProvider",
        "workspaceSymbolProvider",
    ] {
        assert_eq!(caps[c], json!(true), "{c} is advertised");
    }
}
