//! `scylla-mcp <artifact.scylla>` — an MCP server (newline-delimited JSON-RPC over stdio)
//! that lets an agent drive a reverse-engineering session over the client port.

use std::io::{BufRead, Write};

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: scylla-mcp <artifact.scylla>");
            std::process::exit(2);
        }
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: reading {path}: {e}");
        std::process::exit(1);
    });
    let mut session = scylla_port::Session::from_artifact(&bytes).unwrap_or_else(|e| {
        eprintln!("error: decoding artifact: {e}");
        std::process::exit(1);
    });

    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // JSON-RPC notifications (no id) get no response.
        if req.get("id").is_none() {
            continue;
        }
        let resp = scylla_mcp::dispatch(&mut session, &req);
        let _ = writeln!(out, "{resp}");
        let _ = out.flush();
    }
}
