//! `scylla-lsp <artifact.scylla>` — an LSP head (DD-017): a Language Server so an editor navigates a
//! `.scylla` model like source. It speaks LSP's `Content-Length`-framed JSON-RPC over stdin/stdout
//! and forwards each request to `scylla_lsp::dispatch`, the pure port projection. The program is one
//! virtual document (`scylla:program`) — functions in address order — so go-to-symbol, hover,
//! find-references (= callers), rename, and workspace-symbol (= search) all work in the editor.
//!
//! Wire it up in an editor by pointing its LSP client at `scylla-lsp <artifact.scylla>` for, say,
//! the `scylla` language; it serves the one synthetic document.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use scylla_port::Session;
use serde_json::Value;

const USAGE: &str = "usage: scylla-lsp <artifact.scylla>";

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if path == "-h" || path == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-lsp: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut session = match Session::from_artifact(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-lsp: cannot load {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = io::stdout();

    loop {
        match read_message(&mut reader) {
            Ok(Some(req)) => {
                // `exit` stops the loop (it's a notification — dispatch won't reply to it).
                if req.get("method").and_then(Value::as_str) == Some("exit") {
                    break;
                }
                if let Some(resp) = scylla_lsp::dispatch(&mut session, &req) {
                    if write_message(&mut stdout, &resp).is_err() {
                        break; // the client closed the pipe
                    }
                }
            }
            Ok(None) => break, // EOF
            Err(_) => break,
        }
    }
    ExitCode::SUCCESS
}

/// Read one `Content-Length`-framed LSP message: header lines (CRLF-terminated) up to a blank line,
/// then exactly `Content-Length` bytes of JSON body. `Ok(None)` at clean EOF.
fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None); // EOF
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
        // Other headers (Content-Type, …) are ignored.
    }
    if content_length == 0 {
        return Ok(Some(Value::Null));
    }
    let mut buf = vec![0u8; content_length];
    reader.read_exact(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf).unwrap_or(Value::Null)))
}

/// Write one `Content-Length`-framed LSP message.
fn write_message<W: Write>(writer: &mut W, msg: &Value) -> io::Result<()> {
    let body = msg.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    writer.flush()
}
