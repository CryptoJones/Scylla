//! MCP head (DD-022/024) — the first, differentiating adapter: AI agents reverse-engineer
//! binaries by driving the [`scylla_port`] client port over MCP.
//!
//! **No domain logic here (P6 / DD-025).** Every tool is a 1:1 translation onto a
//! `Session` call; the head only marshals JSON ↔ port. The dispatch is pure (testable
//! without stdio); `main.rs` wraps it in the newline-delimited JSON-RPC stdio loop.

use scylla_model::StableId;
use scylla_port::{FunctionView, Session, Zoom};
use serde_json::{json, Value};

fn zoom_from(v: Option<&Value>) -> Zoom {
    match v.and_then(Value::as_str) {
        Some("intent") => Zoom::Intent,
        Some("detail") => Zoom::Detail,
        _ => Zoom::Domain,
    }
}

fn view_json(v: &FunctionView) -> Value {
    json!({
        "id": v.id.0,
        "name": v.name,
        "summary": v.summary,
        "addr": v.addr,
        "bb_count": v.bb_count,
        "callees": v.callees,
        "callers": v.callers,
        "size": v.size,
    })
}

/// The MCP tool catalog — a 1:1 projection of the client port's verbs.
pub fn tools() -> Value {
    json!([
        {"name": "list_functions",
         "description": "List functions at a zoom altitude (intent|domain|detail).",
         "inputSchema": {"type": "object", "properties": {"zoom": {"type": "string"}}}},
        {"name": "get_function",
         "description": "Get one function by stable id at a zoom altitude.",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}, "zoom": {"type": "string"}}, "required": ["id"]}},
        {"name": "callers",
         "description": "List the functions that call a given function.",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}},
        {"name": "rename",
         "description": "Rename a function (durable user fact).",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}, "required": ["id", "name"]}},
        {"name": "comment",
         "description": "Attach a comment to a function (durable user fact).",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}, "text": {"type": "string"}}, "required": ["id", "text"]}}
    ])
}

/// Execute a tool call against the session. Pure translation — no domain logic (P6).
pub fn call_tool(session: &mut Session, name: &str, args: &Value) -> Result<Value, String> {
    let want_id = || {
        args.get("id")
            .and_then(Value::as_u64)
            .map(StableId)
            .ok_or_else(|| "missing or invalid 'id'".to_string())
    };
    match name {
        "list_functions" => Ok(Value::Array(
            session.functions(zoom_from(args.get("zoom"))).iter().map(view_json).collect(),
        )),
        "get_function" => session
            .view(want_id()?, zoom_from(args.get("zoom")))
            .map(|v| view_json(&v))
            .map_err(|e| e.to_string()),
        "callers" => {
            let id = want_id()?;
            Ok(Value::Array(
                session
                    .callers(id)
                    .iter()
                    .map(|c| json!({"id": c.0, "name": session.program().display_name(*c)}))
                    .collect(),
            ))
        }
        "rename" => {
            let name = args.get("name").and_then(Value::as_str).ok_or("missing 'name'")?;
            session.rename(want_id()?, name).map(|_| json!({"ok": true})).map_err(|e| e.to_string())
        }
        "comment" => {
            let text = args.get("text").and_then(Value::as_str).ok_or("missing 'text'")?;
            session.comment(want_id()?, text).map(|_| json!({"ok": true})).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

/// Handle one JSON-RPC request, returning the response value (MCP over JSON-RPC 2.0).
pub fn dispatch(session: &mut Session, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "initialize" => json!({"jsonrpc": "2.0", "id": id, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "scylla-mcp", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}}
        }}),
        "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools()}}),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match call_tool(session, name, &args) {
                Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "content": [{"type": "text", "text": v.to_string()}]
                }}),
                Err(e) => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "content": [{"type": "text", "text": e}], "isError": true
                }}),
            }
        }
        _ => json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": format!("method not found: {method}")}}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATHLIB: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

    fn session() -> Session {
        Session::open(scylla_ingest::snapshot_to_program(MATHLIB).unwrap())
    }

    fn id_of(s: &Session, name: &str) -> u64 {
        s.program().functions.iter().find(|f| f.name == name).unwrap().id.0
    }

    #[test]
    fn tools_list_projects_the_port() {
        let mut s = session();
        let resp = dispatch(&mut s, &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        for expected in ["list_functions", "get_function", "callers", "rename", "comment"] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[test]
    fn get_function_navigates_the_graph() {
        let mut s = session();
        let main = id_of(&s, "main");
        let resp = dispatch(&mut s, &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_function", "arguments": {"id": main, "zoom": "domain"}}
        }));
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("gcd"), "main's callees should include gcd, got: {text}");
    }

    #[test]
    fn rename_through_the_tool_persists_in_the_session() {
        let mut s = session();
        let gcd = id_of(&s, "gcd");
        let r = dispatch(&mut s, &json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "rename", "arguments": {"id": gcd, "name": "euclid_gcd"}}
        }));
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("\"ok\":true"));
        let g = dispatch(&mut s, &json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "get_function", "arguments": {"id": gcd}}
        }));
        assert!(g["result"]["content"][0]["text"].as_str().unwrap().contains("euclid_gcd"));
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let mut s = session();
        let resp = dispatch(&mut s, &json!({"jsonrpc": "2.0", "id": 9, "method": "nope"}));
        assert_eq!(resp["error"]["code"], -32601);
    }

    /// DD-025 / P6: the core must never depend on a head. Enforced mechanically.
    #[test]
    fn core_does_not_depend_on_the_head() {
        let model = include_str!("../../scylla-model/Cargo.toml");
        let port = include_str!("../../scylla-port/Cargo.toml");
        let schema = include_str!("../../scylla-schema/Cargo.toml");
        for (who, toml) in [("model", model), ("port", port), ("schema", schema)] {
            assert!(!toml.contains("scylla-mcp"), "scylla-{who} must not depend on the MCP head (P6/DD-025)");
        }
    }

    #[test]
    fn dispatch_is_total_on_hostile_jsonrpc() {
        // DD-039 per-commit replay: hostile/malformed JSON-RPC must never panic, and must
        // always come back as a well-formed envelope (jsonrpc 2.0 + exactly one of result/error).
        let mut s = session();
        let hostile = [
            json!({}),
            json!(null),
            json!([]),
            json!("string"),
            json!({"method": 123}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_function"}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_function", "arguments": {"id": "not-a-number"}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "💀", "arguments": {}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rename", "arguments": {"id": 1}}}),
        ];
        for req in &hostile {
            let resp = dispatch(&mut s, req);
            assert_eq!(resp["jsonrpc"], "2.0", "must be a JSON-RPC 2.0 envelope: {resp}");
            let has_result = resp.get("result").is_some();
            let has_error = resp.get("error").is_some();
            assert!(has_result ^ has_error, "exactly one of result/error: {resp}");
        }
    }
}
