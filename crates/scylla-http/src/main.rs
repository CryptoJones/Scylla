//! `scylla-http <artifact.scylla> [host:port]` — an HTTP/JSON gateway head (DD-017): query AND
//! annotate a loaded `.scylla` model over plain HTTP, so ANY language / dashboard / `curl` can drive
//! it without the WASM head or the capnp RPC client. One resident session; annotations (the same
//! verbs the RPC head carries) mutate it in place and are reflected on subsequent reads — write
//! routes are gated by the same token as reads. Default `127.0.0.1:8800`.
//!
//!   GET  /                         — this endpoint list
//!   GET  /api/info                 — {name, language, functions}
//!   GET  /api/functions[?zoom=]    — [{id, name, summary}] (sorted by name)
//!   GET  /api/search?q=<query>     — functions whose name contains <query> (case-insensitive)
//!   GET  /api/functions/<id>[?zoom=] — one function's view {id,name,summary,addr,bb_count,size,callees,callers,comment,type}
//!   GET  /api/functions/<id>/callers — [{id, name}]
//!   POST /api/functions/<id>/rename  — body {"name": "…"}   (DD-005 durable user fact)
//!   POST /api/functions/<id>/retype  — body {"type": "…"}
//!   POST /api/functions/<id>/comment — body {"text": "…"}   (may be empty — clears it)
//!   POST /api/diff                 — body = a .scylla; → {matched, renamed, modified, added, removed}
//!   GET  /api/export               — download the resident model, INCLUDING your annotations, as a .scylla

use std::io::Read;
use std::process::ExitCode;

use scylla_model::{FactKind, Program, StableId};
use scylla_port::{Session, Zoom};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

const USAGE: &str = "usage: scylla-http <artifact.scylla> [host:port]   (default 127.0.0.1:8800)";

/// Reject a request body larger than this — `read_to_end` is otherwise unbounded, so one POST can
/// OOM the process. 64 MiB matches the artifact loader's traversal ceiling.
const MAX_BODY: u64 = 64 * 1024 * 1024;

/// Constant-time byte comparison: no early exit on the first differing byte and length folded in, so
/// response timing leaks neither the token's length nor a matching prefix (the bearer-token oracle).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= u64::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Read a request body capped at [`MAX_BODY`]: `Err` on an unreadable body (400) or one over the cap
/// (413), instead of the unbounded `read_to_end` that a hostile client can use to exhaust memory.
fn read_body_capped(req: &mut Request) -> Result<Vec<u8>, (u16, String)> {
    let mut buf = Vec::new();
    if req.as_reader().take(MAX_BODY + 1).read_to_end(&mut buf).is_err() {
        return Err((400, json!({"error": "could not read the request body"}).to_string()));
    }
    if buf.len() as u64 > MAX_BODY {
        return Err((413, json!({"error": "request body too large"}).to_string()));
    }
    Ok(buf)
}

/// Minimal percent-decoding for query values (`%20`/`+` -> space); invalid escapes pass through.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match (
                    (b[i + 1] as char).to_digit(16),
                    (b[i + 2] as char).to_digit(16),
                ) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A routed response: a JSON document (the common case) or the raw model bytes (`/api/export`).
enum Reply {
    Json(u16, String),
    Octet(Vec<u8>),
}

impl From<(u16, String)> for Reply {
    fn from((status, body): (u16, String)) -> Self {
        Reply::Json(status, body)
    }
}

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
    let raw_token = std::env::var("SCYLLA_HTTP_TOKEN").ok();
    if raw_token.as_deref().is_some_and(|t| t.trim().is_empty()) {
        eprintln!(
            "scylla-http: SCYLLA_HTTP_TOKEN is set but empty/blank — the server stays OPEN. Set a \
             non-empty token to gate access, or unset it deliberately."
        );
    }
    // A blank/whitespace-only value is treated as unset (never as a real — trivially weak — token).
    let token = raw_token.filter(|t| !t.trim().is_empty());

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
        (None, None) => None,
        // Fail CLOSED: one of the pair set without the other is a misconfiguration. Silently serving
        // plaintext here would put the token + the whole model on the wire in the clear — exactly
        // what enabling TLS was meant to prevent.
        (cert, _) => {
            let missing = if cert.is_some() {
                "SCYLLA_HTTP_TLS_KEY"
            } else {
                "SCYLLA_HTTP_TLS_CERT"
            };
            eprintln!(
                "scylla-http: TLS is half-configured — {missing} is not set. Refusing to serve \
                 plaintext; set both or neither."
            );
            return ExitCode::FAILURE;
        }
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

    // Precompute the expected Authorization value once (not per request); compared in constant time.
    let expected_bearer = token.as_ref().map(|t| format!("Bearer {t}"));

    for mut request in server.incoming_requests() {
        let reply = if authorized(&request, &expected_bearer) {
            // A panic in a route handler must not take the whole (single-threaded) server down —
            // return 500 for this one request and keep serving.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle(&mut session, &mut request)
            }))
            .unwrap_or_else(|_| Reply::Json(500, json!({"error": "internal error"}).to_string()))
        } else {
            Reply::Json(
                401,
                json!({"error": "unauthorized — send Authorization: Bearer <token>"}).to_string(),
            )
        };
        let (status, ctype, body): (u16, &str, Vec<u8>) = match reply {
            Reply::Json(s, b) => (s, "application/json", b.into_bytes()),
            Reply::Octet(b) => (200, "application/octet-stream", b),
        };
        let ctype_header = Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes())
            .expect("a static Content-Type header is always valid");
        let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..])
            .expect("a static header is always valid");
        let resp = Response::from_data(body)
            .with_status_code(status)
            .with_header(ctype_header)
            .with_header(nosniff);
        let _ = request.respond(resp);
    }
    ExitCode::SUCCESS
}

/// True if the request is allowed: the server is open (`token` is `None`) or the request carries a
/// matching `Authorization: Bearer <token>` header.
fn authorized(req: &Request, expected_bearer: &Option<String>) -> bool {
    let Some(want) = expected_bearer else {
        return true; // OPEN mode (no token configured)
    };
    req.headers().iter().any(|h| {
        h.field.equiv("Authorization")
            && constant_time_eq(h.value.as_str().as_bytes(), want.as_bytes())
    })
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
    let buf = read_body_capped(req)?;
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

/// Route one request to a [`Reply`]. GETs read; the POST annotation routes mutate the resident
/// session in place (hence `&mut`); `/api/diff` consumes a POSTed artifact without mutating;
/// `/api/export` serializes the (possibly annotated) session back to a `.scylla` for download.
fn handle(session: &mut Session, req: &mut Request) -> Reply {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let zoom = zoom_of(query_param(query, "zoom"));
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (&method, segs.as_slice()) {
        (Method::Get, []) => Reply::Json(200, help()),
        (Method::Get, ["api", "info"]) => Reply::Json(200, info(session)),
        (Method::Get, ["api", "functions"]) => Reply::Json(200, functions(session, zoom)),
        (Method::Get, ["api", "search"]) => Reply::Json(
            200,
            search(session, &percent_decode(query_param(query, "q").unwrap_or("")), zoom),
        ),
        (Method::Get, ["api", "functions", id]) => view(session, id, zoom).into(),
        (Method::Get, ["api", "functions", id, "callers"]) => callers(session, id).into(),
        // The resident model — with any annotations made this session — as a downloadable .scylla
        // (DD-026). The HTTP-native counterpart of the MCP head's `export`: a remote client can pull
        // its work back out, since in-memory annotations otherwise die with the server.
        (Method::Get, ["api", "export"]) => Reply::Octet(session.to_artifact()),
        (Method::Post, ["api", "functions", id, "rename"]) => rename(session, id, req).into(),
        (Method::Post, ["api", "functions", id, "retype"]) => retype(session, id, req).into(),
        (Method::Post, ["api", "functions", id, "comment"]) => comment(session, id, req).into(),
        (Method::Post, ["api", "diff"]) => diff(session, req).into(),
        _ => Reply::Json(404, json!({"error": "not found"}).to_string()),
    }
}

fn help() -> String {
    json!({
        "service": "scylla-http",
        "endpoints": [
            "GET /api/info",
            "GET /api/functions?zoom=intent|domain|detail",
            "GET /api/search?q=<query>&zoom=…",
            "GET /api/functions/<id>?zoom=…",
            "GET /api/functions/<id>/callers",
            "POST /api/functions/<id>/rename (body: {\"name\": \"…\"})",
            "POST /api/functions/<id>/retype (body: {\"type\": \"…\"})",
            "POST /api/functions/<id>/comment (body: {\"text\": \"…\"})",
            "POST /api/diff (body: a .scylla artifact)",
            "GET /api/export (download the annotated model as a .scylla)",
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

/// `GET /api/search?q=<query>[&zoom=]` — functions whose display name contains `q`
/// (case-insensitive), sorted by name; same `{id, name, summary}` shape as `functions`.
fn search(session: &Session, q: &str, zoom: Zoom) -> String {
    let arr: Vec<Value> = session
        .search(q, zoom)
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
    let bytes = match read_body_capped(req) {
        Ok(b) => b,
        Err(e) => return e,
    };
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
    // Match-confidence breakdown by ladder rung (DD-017): exact is certain, fuzzy a best-guess.
    let mut methods = serde_json::Map::new();
    let mut confidence = serde_json::Map::new();
    for (name, info) in &d.provenance {
        let e = methods.entry(info.method.as_str()).or_insert(json!(0));
        *e = json!(e.as_u64().unwrap_or(0) + 1);
        confidence.insert(
            name.clone(),
            json!({"method": info.method.as_str(), "confidence": info.confidence}),
        );
    }
    (
        200,
        json!({
            "matched": unchanged,
            "renamed": pairs(&renamed),
            "modified": pairs(&d.changed),
            "added": d.only_there,
            "removed": d.only_here,
            "methods": Value::Object(methods),
            "confidence": Value::Object(confidence),
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
