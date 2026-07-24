//! `scylla-lsp <artifact.scylla>` — an LSP head (DD-017): a Language Server so an editor navigates a
//! `.scylla` model like source. It speaks LSP's `Content-Length`-framed JSON-RPC over stdin/stdout
//! and forwards each request to `scylla_lsp::dispatch`, the pure port projection. The program is one
//! virtual document (`scylla:program`) — functions in address order — so go-to-symbol, hover,
//! find-references (= callers), rename, and workspace-symbol (= search) all work in the editor.
//!
//! Wire it up in an editor by pointing its LSP client at `scylla-lsp <artifact.scylla>` for, say,
//! the `scylla` language; it serves the one synthetic document.

use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;

use scylla_port::Session;
use serde_json::{json, Value};

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
            Err(ReadMessageError::Json(err)) => {
                eprintln!("scylla-lsp: malformed JSON request: {err}");
                if write_message(&mut stdout, &json_rpc_error(-32700, "Parse error")).is_err() {
                    break;
                }
            }
            Err(ReadMessageError::Framing(message)) => {
                eprintln!("scylla-lsp: malformed LSP frame: {message}");
                let _ = write_message(&mut stdout, &json_rpc_error(-32600, "Invalid Request"));
                // The unread body length is unknown, so the stream cannot be safely resynchronized.
                break;
            }
            Err(ReadMessageError::Io(err)) => {
                eprintln!("scylla-lsp: input error: {err}");
                break;
            }
        }
    }
    ExitCode::SUCCESS
}

#[derive(Debug)]
enum ReadMessageError {
    Io(io::Error),
    Framing(&'static str),
    Json(serde_json::Error),
}

impl From<io::Error> for ReadMessageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Read one `Content-Length`-framed LSP message: header lines (CRLF-terminated) up to a blank line,
/// then exactly `Content-Length` bytes of JSON body. `Ok(None)` at clean EOF. Bounded on BOTH the
/// header line length and the body size, so a hostile/buggy client can't drive an unbounded
/// allocation (`Content-Length: 99999999999999` would otherwise attempt a multi-TB `vec!` up front).
fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>, ReadMessageError> {
    /// A single header line this long without a newline is malformed/hostile.
    const MAX_HEADER_LINE: u64 = 8 * 1024;
    /// A body larger than this is refused rather than allocated (a Content-Length DoS bound).
    const MAX_BODY: usize = 32 * 1024 * 1024;

    let mut content_length = None;
    loop {
        let mut line = String::new();
        let n = <&mut R as Read>::take(&mut *reader, MAX_HEADER_LINE).read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        // A header line that hit the cap without terminating is malformed/hostile — refuse it.
        if !line.ends_with('\n') {
            return Err(ReadMessageError::Framing(if n as u64 >= MAX_HEADER_LINE {
                "header line too long"
            } else {
                "unterminated header line"
            }));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                if content_length.is_some() {
                    return Err(ReadMessageError::Framing("duplicate Content-Length header"));
                }
                content_length = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| ReadMessageError::Framing("invalid Content-Length header"))?,
                );
            }
        }
        // Other headers (Content-Type, …) are ignored.
    }
    let content_length =
        content_length.ok_or(ReadMessageError::Framing("missing Content-Length header"))?;
    // Refuse an over-large (or garbage-huge) Content-Length instead of allocating it up front.
    if content_length > MAX_BODY {
        return Err(ReadMessageError::Framing(
            "Content-Length exceeds the maximum",
        ));
    }
    if content_length == 0 {
        return Err(ReadMessageError::Framing(
            "Content-Length must be greater than zero",
        ));
    }
    let mut buf = vec![0u8; content_length];
    if let Err(error) = reader.read_exact(&mut buf) {
        return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
            ReadMessageError::Framing("body is shorter than Content-Length")
        } else {
            ReadMessageError::Io(error)
        });
    }
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(ReadMessageError::Json)
}

fn json_rpc_error(code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Write one `Content-Length`-framed LSP message.
fn write_message<W: Write>(writer: &mut W, msg: &Value) -> io::Result<()> {
    let body = msg.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn reads_a_valid_message() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let frame = format!(
            "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc\r\n\r\n",
            body.len()
        );
        let mut bytes = frame.into_bytes();
        bytes.extend_from_slice(body);

        let message = read_message(&mut Cursor::new(bytes))
            .expect("valid frame")
            .expect("one message");
        assert_eq!(message["method"], "initialize");
    }

    #[test]
    fn rejects_invalid_content_length() {
        let mut input = Cursor::new(b"Content-Length: nope\r\n\r\n".as_slice());
        assert!(matches!(
            read_message(&mut input),
            Err(ReadMessageError::Framing("invalid Content-Length header"))
        ));
    }

    #[test]
    fn rejects_missing_and_zero_content_length() {
        let mut missing = Cursor::new(b"Content-Type: application/json\r\n\r\n".as_slice());
        assert!(matches!(
            read_message(&mut missing),
            Err(ReadMessageError::Framing("missing Content-Length header"))
        ));

        let mut zero = Cursor::new(b"Content-Length: 0\r\n\r\n".as_slice());
        assert!(matches!(
            read_message(&mut zero),
            Err(ReadMessageError::Framing(
                "Content-Length must be greater than zero"
            ))
        ));
    }

    #[test]
    fn rejects_unterminated_headers_and_short_bodies() {
        let mut unterminated = Cursor::new(b"Content-Length: 1".as_slice());
        assert!(matches!(
            read_message(&mut unterminated),
            Err(ReadMessageError::Framing("unterminated header line"))
        ));

        let mut short = Cursor::new(b"Content-Length: 2\r\n\r\n{".as_slice());
        assert!(matches!(
            read_message(&mut short),
            Err(ReadMessageError::Framing(
                "body is shorter than Content-Length"
            ))
        ));
    }

    #[test]
    fn reports_malformed_json_separately_from_framing() {
        let mut input = Cursor::new(b"Content-Length: 1\r\n\r\n{".as_slice());
        assert!(matches!(
            read_message(&mut input),
            Err(ReadMessageError::Json(_))
        ));
    }

    #[test]
    fn error_response_has_json_rpc_error_shape() {
        assert_eq!(
            json_rpc_error(-32700, "Parse error"),
            json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32700, "message": "Parse error"}
            })
        );
    }
}
