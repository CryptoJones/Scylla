//! `scylla-serve <artifact.scylla> [port]` — the native single-binary head (DD-028 / Sprint 8):
//! a self-contained binary that serves the **embedded WASM head** + your `.scylla` model-artifact
//! over HTTP, so a browser navigates/annotates the model with **no JVM, no server runtime, no
//! toolchain**. The WASM head (index.html + scylla_wasm.wasm) is baked in at compile time; the
//! artifact is read at startup and served where the head fetches it.
//!
//! Zero dependencies (std only) — a hand-rolled HTTP/1.1 static responder, thread-per-connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

// The WASM head, baked in (the committed prebuilt assets). One binary, no external files.
const INDEX_HTML: &str = include_str!("../../scylla-wasm/web/index.html");
const WASM: &[u8] = include_bytes!("../../scylla-wasm/web/scylla_wasm.wasm");

const USAGE: &str = "usage: scylla-serve <artifact.scylla> [compare.scylla] [port]   (default port 8000)\n\
                     a second .scylla is served as the compare build — the browser auto-diffs against it";

fn read_or_die(what: &str, path: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-serve: cannot read {what} {path}: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(artifact_path) = args.next() else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    if artifact_path == "-h" || artifact_path == "--help" {
        println!("{USAGE}");
        return;
    }
    // The remaining args are a port and/or a second `.scylla` (the compare build), in any order:
    // a token that parses as a u16 is the port; one ending `.scylla` is the compare artifact.
    let mut port: u16 = 8000;
    let mut compare_path: Option<String> = None;
    for a in args {
        if let Ok(p) = a.parse::<u16>() {
            port = p;
        } else if a.ends_with(".scylla") {
            compare_path = Some(a);
        } else {
            eprintln!("scylla-serve: ignoring unrecognized argument {a:?}");
        }
    }

    let artifact = read_or_die("artifact", &artifact_path);
    let compare = compare_path.as_ref().map(|p| read_or_die("compare", p));

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("scylla-serve: cannot bind 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    match (&compare_path, &compare) {
        (Some(cp), Some(c)) => println!(
            "scylla-serve: {} ({} bytes) vs compare {} ({} bytes) → http://127.0.0.1:{port}/  (Ctrl-C to stop)",
            artifact_path, artifact.len(), cp, c.len()
        ),
        _ => println!(
            "scylla-serve: {} ({} bytes) → http://127.0.0.1:{port}/  (Ctrl-C to stop)",
            artifact_path, artifact.len()
        ),
    }

    let artifact: &'static [u8] = Box::leak(artifact.into_boxed_slice());
    let compare: Option<&'static [u8]> = compare.map(|c| &*Box::leak(c.into_boxed_slice()));
    for stream in listener.incoming().flatten() {
        thread::spawn(move || {
            let _ = handle(stream, artifact, compare);
        });
    }
}

fn handle(mut stream: TcpStream, artifact: &[u8], compare: Option<&[u8]>) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    // The request path is the 2nd token of the request line; strip any query string.
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let path = path.split('?').next().unwrap_or("/");

    // The head fetches `mathlib.scylla` (its baked default name) — serve the user's artifact there;
    // and `compare.scylla` when a second build was given (the head auto-diffs against it on boot).
    let (status, ctype, body): (&str, &str, &[u8]) = match path {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        "/scylla_wasm.wasm" => ("200 OK", "application/wasm", WASM),
        "/mathlib.scylla" => ("200 OK", "application/octet-stream", artifact),
        "/compare.scylla" => match compare {
            Some(c) => ("200 OK", "application/octet-stream", c),
            None => ("404 Not Found", "text/plain; charset=utf-8", b"not found"),
        },
        _ => ("404 Not Found", "text/plain; charset=utf-8", b"not found"),
    };

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}
