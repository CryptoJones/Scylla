//! `scylla-http <artifact.scylla> [host:port]` — an HTTP/JSON gateway head (DD-017): query AND
//! annotate a loaded `.scylla` model over plain HTTP, so ANY language / dashboard / `curl` can drive
//! it without the WASM head or the capnp RPC client. One resident session; annotations (the same
//! verbs the RPC head carries) mutate it in place and are reflected on subsequent reads — write
//! routes are gated by the same token as reads. Default `127.0.0.1:8800`.
//!
//!   GET  /                         — this endpoint list
//!   GET  /api/info                 — {name, language, functions}
//!   GET  /api/functions[?zoom=]    — [{id, name, summary}] (sorted by name)
//!   GET  /api/functions/<id>[?zoom=] — one function's view {id,name,summary,addr,bb_count,size,callees,callers,comment,type}
//!   GET  /api/functions/<id>/callers — [{id, name}]
//!   POST /api/functions/<id>/rename  — body {"name": "…"}   (DD-005 durable user fact)
//!   POST /api/functions/<id>/retype  — body {"type": "…"}
//!   POST /api/functions/<id>/comment — body {"text": "…"}   (may be empty — clears it)
//!   POST /api/diff                 — body = a .scylla; → {matched, renamed, modified, added, removed}

use std::process::ExitCode;

use scylla_model::{FactKind, Program, StableId};
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
    // One resident session, mutated in place by the annotation routes (the loop is single-threaded —
    // tiny_http hands us one request at a time — so an owned `&mut` is sufficient; no lock needed).
    let mut session = match Session::from_artifact(&bytes) {
        Ok(s) => s,
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

    // Optional TLS (DD-035): with SCYLLA_HTTP_TLS_CERT + SCYLLA_HTTP_TLS_KEY (PEM), serve HTTPS so
    // the token + the model don't cross the wire in the clear. (Many deployments TLS-terminate at a
    // reverse proxy instead — this is the self-contained option, mirroring the RPC head.)
    let tls = match (
        std::env::var("SCYLLA_HTTP_TLS_CERT").ok(),
        std::env::var("SCYLLA_HTTP_TLS_KEY").ok(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(&cert_path).unwrap_or_else(|e| {
                eprintln!("scylla-http: cannot read TLS cert {cert_path}: {e}");
                std::process::exit(1);
            });
            let key = std::fs::read(&key_path).unwrap_or_else(|e| {
                eprintln!("scylla-http: cannot read TLS key {key_path}: {e}");
                std::process::exit(1);
            });
            Some((cert, key))
        }
        _ => None,
    };

    let scheme = if tls.is_some() { "https" } else { "http" };
    let server = match tls {
        Some((certificate, private_key)) => Server::https(
            &addr,
            tiny_http::SslConfig {
                certificate,
                private_key,
            },
        ),
        None => Server::http(&addr),
    };
    let server = match server {
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
        "scylla-http: {artifact} on {scheme}://{addr}/  — {auth} (DD-017 JSON gateway; Ctrl-C to stop)"
    );

    for mut request in server.incoming_requests() {
        let (status, body) = if authorized(&request, &token) {
            handle(&mut session, &mut request)
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

/// Parse a path id segment to a `StableId`, or a `400` on non-integer input.
fn parse_id(id: &str) -> Result<StableId, (u16, String)> {
    id.parse::<u64>()
        .map(StableId)
        .map_err(|_| (400, json!({"error": "id must be an integer"}).to_string()))
}

/// Read a POST body and parse it as JSON, or a `400` on an unreadable / malformed body.
fn json_body(req: &mut Request) -> Result<Value, (u16, String)> {
    let mut buf = Vec::new();
    if req.as_reader().read_to_end(&mut buf).is_err() {
        return Err((
            400,
            json!({"error": "could not read the request body"}).to_string(),
        ));
    }
    serde_json::from_slice(&buf).map_err(|e| {
        (
            400,
            json!({"error": format!("invalid JSON body: {e}")}).to_string(),
        )
    })
}

/// The user comment attached to `id` (DD-005 durable fact), if any.
fn comment_of(prog: &Program, id: StableId) -> Option<String> {
    prog.facts.iter().find_map(|f| match &f.kind {
        FactKind::Comment(c) if f.target == id => Some(c.clone()),
        _ => None,
    })
}

/// The user-assigned type for `id`, if any.
fn type_of(prog: &Program, id: StableId) -> Option<String> {
    prog.facts.iter().find_map(|f| match &f.kind {
        FactKind::Retype(t) if f.target == id => Some(t.clone()),
        _ => None,
    })
}

/// Route one request to `(status, json_body)`. GETs read; the POST annotation routes mutate the
/// resident session in place (hence `&mut`); `/api/diff` consumes a POSTed artifact without mutating.
fn handle(session: &mut Session, req: &mut Request) -> (u16, String) {
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
        (Method::Post, ["api", "functions", id, "rename"]) => rename(session, id, req),
        (Method::Post, ["api", "functions", id, "retype"]) => retype(session, id, req),
        (Method::Post, ["api", "functions", id, "comment"]) => comment(session, id, req),
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
            "POST /api/functions/<id>/rename (body: {\"name\": \"…\"})",
            "POST /api/functions/<id>/retype (body: {\"type\": \"…\"})",
            "POST /api/functions/<id>/comment (body: {\"text\": \"…\"})",
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
    let sid = match parse_id(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match session.view(sid, zoom) {
        Ok(v) => {
            let prog = session.program();
            (
                200,
                json!({
                    "id": v.id.0, "name": v.name, "summary": v.summary, "addr": v.addr,
                    "bb_count": v.bb_count, "size": v.size, "callees": v.callees, "callers": v.callers,
                    "comment": comment_of(prog, sid), "type": type_of(prog, sid),
                })
                .to_string(),
            )
        }
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

/// Shared spine of the three annotation routes: resolve the id (404 if unknown), read a JSON body,
/// pull the string `field`, and apply the port verb — mapping a port error to `400`. The mutation
/// lands on the resident session and shows up on the next read (DD-005 durable user fact).
fn annotate(
    session: &mut Session,
    id: &str,
    req: &mut Request,
    field: &str,
    apply: impl FnOnce(&mut Session, StableId, String) -> Result<(), scylla_port::PortError>,
) -> (u16, String) {
    let sid = match parse_id(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !session.program().functions.iter().any(|f| f.id == sid) {
        return (
            404,
            json!({"error": format!("no function with id {}", sid.0)}).to_string(),
        );
    }
    let body = match json_body(req) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let Some(val) = body.get(field).and_then(|v| v.as_str()) else {
        return (
            400,
            json!({"error": format!("expected a string field `{field}`")}).to_string(),
        );
    };
    match apply(session, sid, val.to_string()) {
        Ok(()) => (200, json!({"ok": true, "id": sid.0}).to_string()),
        Err(e) => (400, json!({"error": e.to_string()}).to_string()),
    }
}

fn rename(session: &mut Session, id: &str, req: &mut Request) -> (u16, String) {
    annotate(session, id, req, "name", |s, i, v| s.rename(i, v))
}

fn retype(session: &mut Session, id: &str, req: &mut Request) -> (u16, String) {
    annotate(session, id, req, "type", |s, i, v| s.retype(i, v))
}

fn comment(session: &mut Session, id: &str, req: &mut Request) -> (u16, String) {
    annotate(session, id, req, "text", |s, i, v| s.comment(i, v))
}
