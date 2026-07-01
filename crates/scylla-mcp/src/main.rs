//! `scylla-mcp <artifact.scylla>` — an MCP server (newline-delimited JSON-RPC over stdio)
//! that lets an agent drive a reverse-engineering session over the client port.

use std::io::{BufRead, Read, Write};

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

    // Cap a single JSON-RPC line so a newline-less flood can't drive an unbounded allocation (OOM).
    const MAX_LINE: u64 = 16 * 1024 * 1024;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut out = std::io::stdout();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_LINE + 1).read_until(b'\n', &mut buf) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        if buf.len() as u64 > MAX_LINE {
            eprintln!("scylla-mcp: a request line exceeded {MAX_LINE} bytes — stopping");
            break;
        }
        // A non-UTF-8 line is decoded lossily and (almost certainly) fails to parse -> skipped. One
        // stray byte must NOT terminate the whole server (the old `.lines()` broke on it).
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // JSON-RPC notifications (no id) get no response.
        if req.get("id").is_none() {
            continue;
        }
        let resp = scylla_mcp::dispatch(&mut session, &req);
        // If the client closed its end, stop instead of spinning on a dead pipe.
        if writeln!(out, "{resp}").is_err() || out.flush().is_err() {
            break;
        }
    }
}
