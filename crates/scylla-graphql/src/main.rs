//! `scylla-graphql <artifact.scylla> [host:port]` — a GraphQL head (DD-017): query AND annotate a
//! loaded `.scylla` model as ONE typed graph, so a GraphQL client / dashboard fetches exactly the
//! function / caller / diff shape it wants in a single round-trip — no over- or under-fetching like
//! the fixed REST routes of the HTTP head. The schema IS the port: navigate / search / diff / export
//! as queries, rename / retype / comment as mutations. Default `127.0.0.1:8801`.
//!
//!   GET  /          — a one-line pointer to /graphql
//!   GET  /graphql   — an interactive GraphiQL console (explore the schema, run queries)
//!   POST /graphql   — execute a GraphQL request {query, variables?, operationName?}
//!
//! Access is gated by SCYLLA_GRAPHQL_TOKEN (DD-035, Bearer); TLS by SCYLLA_GRAPHQL_TLS_CERT +
//! SCYLLA_GRAPHQL_TLS_KEY (PEM) — the same self-contained posture as the HTTP and RPC heads.

mod schema;

use std::io::Read;
use std::process::ExitCode;

use juniper::http::GraphQLRequest;
use scylla_port::Session;
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::schema::{schema, Context, Schema};

const USAGE: &str = "usage: scylla-graphql <artifact.scylla> [host:port]   (default 127.0.0.1:8801)";

/// Reject a request body larger than this — `read_to_end` is otherwise unbounded (OOM DoS).
const MAX_BODY: u64 = 64 * 1024 * 1024;

/// Constant-time byte comparison: no early exit and length folded in, so response timing leaks
/// neither the token's length nor a matching prefix (the bearer-token timing oracle).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= u64::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
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
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8801".to_string());

    let bytes = match std::fs::read(&artifact) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-graphql: cannot read {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };
    // One resident session, annotated in place by mutations. The tiny_http loop is single-threaded
    // (one request resolved before the next), so the schema's `RefCell` context is sound — no lock.
    let session = match Session::from_artifact(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-graphql: cannot load {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // SCYLLA_GRAPHQL_TOKEN gates every request (DD-035); unset = OPEN (fine for a loopback dev
    // console, announced loudly otherwise).
    let raw_token = std::env::var("SCYLLA_GRAPHQL_TOKEN").ok();
    if raw_token.as_deref().is_some_and(|t| t.trim().is_empty()) {
        eprintln!(
            "scylla-graphql: SCYLLA_GRAPHQL_TOKEN is set but empty/blank — the server stays OPEN. \
             Set a non-empty token to gate access, or unset it deliberately."
        );
    }
    let token = raw_token.filter(|t| !t.trim().is_empty());

    // Optional TLS (DD-035): both cert + key (PEM) present = HTTPS, else HTTP — mirroring the HTTP head.
    let tls = match (
        std::env::var("SCYLLA_GRAPHQL_TLS_CERT").ok(),
        std::env::var("SCYLLA_GRAPHQL_TLS_KEY").ok(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(&cert_path).unwrap_or_else(|e| {
                eprintln!("scylla-graphql: cannot read TLS cert {cert_path}: {e}");
                std::process::exit(1);
            });
            let key = std::fs::read(&key_path).unwrap_or_else(|e| {
                eprintln!("scylla-graphql: cannot read TLS key {key_path}: {e}");
                std::process::exit(1);
            });
            Some((cert, key))
        }
        (None, None) => None,
        // Fail CLOSED: one of the pair set without the other would silently serve plaintext, putting
        // the token + model on the wire in the clear — the opposite of what TLS was enabling.
        (cert, _) => {
            let missing = if cert.is_some() {
                "SCYLLA_GRAPHQL_TLS_KEY"
            } else {
                "SCYLLA_GRAPHQL_TLS_CERT"
            };
            eprintln!(
                "scylla-graphql: TLS is half-configured — {missing} is not set. Refusing to serve \
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
            eprintln!("scylla-graphql: cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let context = Context::new(session);
    let root = schema();
    let auth = if token.is_some() {
        "token-gated"
    } else {
        "OPEN (set SCYLLA_GRAPHQL_TOKEN to gate)"
    };
    eprintln!(
        "scylla-graphql: {artifact} on {scheme}://{addr}/graphql  — {auth} (DD-017 GraphQL head; Ctrl-C to stop)"
    );

    // Precompute the expected Authorization value once (not per request); compared in constant time.
    let expected_bearer = token.as_ref().map(|t| format!("Bearer {t}"));

    for request in server.incoming_requests() {
        if !authorized(&request, &expected_bearer) {
            respond_json(
                request,
                401,
                &json!({"errors": [{"message": "unauthorized — send Authorization: Bearer <token>"}]})
                    .to_string(),
            );
            continue;
        }
        // A panic in a resolver/handler must not take the whole (single-threaded) server down.
        let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let method = request.method().clone();
            let url = request.url().to_string();
            let path = url.split('?').next().unwrap_or("/");
            match (&method, path) {
                (Method::Get, "/") => respond_json(request, 200, &help()),
                (Method::Get, "/graphql") => respond_html(
                    request,
                    200,
                    &juniper::http::graphiql::graphiql_source("/graphql", None),
                ),
                (Method::Post, "/graphql") => execute(request, &root, &context),
                _ => respond_json(
                    request,
                    404,
                    &json!({"errors": [{"message": "not found — POST a GraphQL request to /graphql"}]})
                        .to_string(),
                ),
            }
        }));
        if handled.is_err() {
            eprintln!("scylla-graphql: a request handler panicked — connection dropped, server continues");
        }
    }
    ExitCode::SUCCESS
}

/// Read the POST body, parse it as a GraphQL request, execute it synchronously against the schema,
/// and serialize the `{data, errors}` response. A malformed request is `400`; an executed request
/// (even one whose resolvers errored) is `200` with the errors in the body — the GraphQL contract.
fn execute(mut request: Request, root: &Schema, context: &Context) {
    let mut body = Vec::new();
    if request.as_reader().take(MAX_BODY + 1).read_to_end(&mut body).is_err() {
        respond_json(
            request,
            400,
            &json!({"errors": [{"message": "could not read the request body"}]}).to_string(),
        );
        return;
    }
    if body.len() as u64 > MAX_BODY {
        respond_json(
            request,
            413,
            &json!({"errors": [{"message": "request body too large"}]}).to_string(),
        );
        return;
    }
    match serde_json::from_slice::<GraphQLRequest>(&body) {
        Ok(gql) => {
            let response = gql.execute_sync(root, context);
            let payload = serde_json::to_string(&response).unwrap_or_else(|e| {
                json!({"errors": [{"message": format!("could not serialize response: {e}")}]})
                    .to_string()
            });
            respond_json(request, 200, &payload);
        }
        Err(e) => respond_json(
            request,
            400,
            &json!({"errors": [{"message": format!("invalid GraphQL request: {e}")}]}).to_string(),
        ),
    }
}

/// True if the server is open (`token` is `None`) or the request carries a matching
/// `Authorization: Bearer <token>` header.
fn authorized(req: &Request, expected_bearer: &Option<String>) -> bool {
    let Some(want) = expected_bearer else {
        return true; // OPEN mode (no token configured)
    };
    req.headers().iter().any(|h| {
        h.field.equiv("Authorization")
            && constant_time_eq(h.value.as_str().as_bytes(), want.as_bytes())
    })
}

fn respond_json(request: Request, status: u16, body: &str) {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("a static Content-Type header is always valid");
    let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..])
        .expect("a static header is always valid");
    let resp = Response::from_string(body)
        .with_status_code(status)
        .with_header(header)
        .with_header(nosniff);
    let _ = request.respond(resp);
}

fn respond_html(request: Request, status: u16, body: &str) {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .expect("a static Content-Type header is always valid");
    let nosniff = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..])
        .expect("a static header is always valid");
    let resp = Response::from_string(body)
        .with_status_code(status)
        .with_header(header)
        .with_header(nosniff);
    let _ = request.respond(resp);
}

fn help() -> String {
    json!({
        "service": "scylla-graphql",
        "graphql": "POST your query to /graphql (interactive GraphiQL console at GET /graphql)",
        "example": "{ info { name language functions } functions(zoom: DOMAIN) { id name summary } }",
    })
    .to_string()
}
