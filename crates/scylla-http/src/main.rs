//! `scylla-http <artifact.scylla> [host:port]` — an HTTP/JSON gateway head (DD-017): query a loaded
//! `.scylla` model over plain HTTP, so ANY language / dashboard / `curl` can read it without the
//! WASM head or the capnp RPC client. Read-only over one resident session (annotations aren't
//! exposed — this is the query/diff surface). Default `127.0.0.1:8800`.
//!
//!   GET  /                         — this endpoint list
//!   GET  /api/info                 — {name, language, functions}
//!   GET  /api/functions[?zoom=]    — [{id, name, summary}] (sorted by name)
//!   GET  /api/functions/<id>[?zoom=] — one function's view {id,name,summary,addr,bb_count,size,callees,callers}
//!   GET  /api/functions/<id>/callers — [{id, name}]
//!   POST /api/diff                 — body = a .scylla; → {matched, renamed, modified, added, removed}

use std::process::ExitCode;
use std::sync::Arc;

use scylla_model::StableId;
use scylla_port::{Session, Zoom};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

const USAGE: &str = "usage: scylla-http <artifact.scylla> [host:port]   (default 127.0.0.1:8800)";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(artifact) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if artifact == "-h" || artifact == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8800".to_string());

    let bytes = match std::fs::read(&artifact) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-http: cannot read {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let session = match Session::from_artifact(&bytes) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("scylla-http: cannot load {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Access is gated by SCYLLA_HTTP_TOKEN (DD-035): every request must carry
    // `Authorization: Bearer <token>`. Unset = OPEN (anyone can query) — fine for a loopback dev
    // gateway, announced loudly otherwise.
    let token = std::env::var("SCYLLA_HTTP_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-http: cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let auth = if token.is_some() {
        "token-gated"
    } else {
        "OPEN (set SCYLLA_HTTP_TOKEN to gate)"
    };
    eprintln!(
        "scylla-http: {artifact} on http://{addr}/  — {auth} (DD-017 JSON gateway; Ctrl-C to stop)"
    );

    for mut request in server.incoming_requests() {
        let (status, body) = if authorized(&request, &token) {
            handle(&session, &mut request)
        } else {
            (
                401,
                json!({"error": "unauthorized — send Authorization: Bearer <token>"}).to_string(),
            )
        };
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let resp = Response::from_string(body)
            .with_status_code(status)
            .with_header(header);
        let _ = request.respond(resp);
    }
    ExitCode::SUCCESS
}

/// True if the request is allowed: the server is open (`token` is `None`) or the request carries a
/// matching `Authorization: Bearer <token>` header.
fn authorized(req: &Request, token: &Option<String>) -> bool {
    let Some(t) = token else {
        return true;
    };
    let want = format!("Bearer {t}");
    req.headers()
        .iter()
        .any(|h| h.field.equiv("Authorization") && h.value.as_str() == want)
}

fn zoom_of(q: Option<&str>) -> Zoom {
    match q {
        Some("intent") => Zoom::Intent,
        Some("detail") => Zoom::Detail,
        _ => Zoom::Domain,
    }
}

/// Pull `key`'s value out of a `&`-joined query string.
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}="))?.into())
}

/// Route one request to `(status, json_body)`. Read-only except it consumes a POSTed diff artifact.
fn handle(session: &Session, req: &mut Request) -> (u16, String) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let zoom = zoom_of(query_param(query, "zoom"));
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (&method, segs.as_slice()) {
        (Method::Get, []) => (200, help()),
        (Method::Get, ["api", "info"]) => (200, info(session)),
        (Method::Get, ["api", "functions"]) => (200, functions(session, zoom)),
        (Method::Get, ["api", "functions", id]) => view(session, id, zoom),
        (Method::Get, ["api", "functions", id, "callers"]) => callers(session, id),
        (Method::Post, ["api", "diff"]) => diff(session, req),
        _ => (404, json!({"error": "not found"}).to_string()),
    }
}

fn help() -> String {
    json!({
        "service": "scylla-http",
        "endpoints": [
            "GET /api/info",
            "GET /api/functions?zoom=intent|domain|detail",
            "GET /api/functions/<id>?zoom=…",
            "GET /api/functions/<id>/callers",
            "POST /api/diff (body: a .scylla artifact)",
        ],
    })
    .to_string()
}

fn info(session: &Session) -> String {
    let p = session.program();
    json!({"name": p.name, "language": p.language, "functions": p.functions.len()}).to_string()
}

fn functions(session: &Session, zoom: Zoom) -> String {
    let mut fns = session.functions(zoom);
    fns.sort_by(|a, b| a.name.cmp(&b.name));
    let arr: Vec<Value> = fns
        .iter()
        .map(|f| json!({"id": f.id.0, "name": f.name, "summary": f.summary}))
        .collect();
    Value::Array(arr).to_string()
}

fn view(session: &Session, id: &str, zoom: Zoom) -> (u16, String) {
    let Ok(id) = id.parse::<u64>() else {
        return (400, json!({"error": "id must be an integer"}).to_string());
    };
    match session.view(StableId(id), zoom) {
        Ok(v) => (
            200,
            json!({
                "id": v.id.0, "name": v.name, "summary": v.summary, "addr": v.addr,
                "bb_count": v.bb_count, "size": v.size, "callees": v.callees, "callers": v.callers,
            })
            .to_string(),
        ),
        Err(e) => (404, json!({"error": e.to_string()}).to_string()),
    }
}

fn callers(session: &Session, id: &str) -> (u16, String) {
    let Ok(id) = id.parse::<u64>() else {
        return (400, json!({"error": "id must be an integer"}).to_string());
    };
    let prog = session.program();
    if !prog.functions.iter().any(|f| f.id == StableId(id)) {
        return (
            404,
            json!({"error": format!("no function with id {id}")}).to_string(),
        );
    }
    let arr: Vec<Value> = session
        .callers(StableId(id))
        .into_iter()
        .map(|c| json!({"id": c.0, "name": prog.display_name(c)}))
        .collect();
    (200, Value::Array(arr).to_string())
}

fn diff(session: &Session, req: &mut Request) -> (u16, String) {
    let mut bytes = Vec::new();
    if req.as_reader().read_to_end(&mut bytes).is_err() {
        return (
            400,
            json!({"error": "could not read the request body"}).to_string(),
        );
    }
    let other = match Session::from_artifact(&bytes) {
        Ok(s) => s,
        Err(e) => {
            return (
                400,
                json!({"error": format!("invalid .scylla: {e}")}).to_string(),
            )
        }
    };
    let d = session.diff(&other);
    let renamed: Vec<(String, String)> =
        d.matched.iter().filter(|(a, b)| a != b).cloned().collect();
    let unchanged = d.matched.len() - renamed.len();
    let pairs =
        |v: &[(String, String)]| v.iter().map(|(a, b)| json!([a, b])).collect::<Vec<Value>>();
    (
        200,
        json!({
            "matched": unchanged,
            "renamed": pairs(&renamed),
            "modified": pairs(&d.changed),
            "added": d.only_there,
            "removed": d.only_here,
        })
        .to_string(),
    )
}
