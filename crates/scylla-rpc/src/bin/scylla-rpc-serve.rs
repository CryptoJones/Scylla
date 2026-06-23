//! `scylla-rpc-serve <artifact.scylla> [host:port]` — serve a loaded `.scylla` model over the
//! DD-002 Cap'n Proto promise-pipelining RPC interface to **remote** clients (the deferred remote
//! head, now real). Default `127.0.0.1:9000`. One resident session; each TCP connection gets its
//! own RPC system over the SAME session (single-threaded `LocalSet` — capnp-rpc capabilities are
//! `!Send`). Read-only-ish: annotations mutate the in-memory session, not the on-disk artifact.

use std::cell::RefCell;
use std::process::ExitCode;
use std::rc::Rc;

use scylla_port::Session;
use scylla_rpc::{serve_with_timeout, tls_acceptor, SharedSession};

const USAGE: &str =
    "usage: scylla-rpc-serve <artifact.scylla> [host:port]   (default 127.0.0.1:9000)";

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
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());

    let bytes = match std::fs::read(&artifact) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("scylla-rpc-serve: cannot read {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let session = match Session::from_artifact(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scylla-rpc-serve: cannot load {artifact}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Access is gated by SCYLLA_RPC_TOKEN (DD-035): a client must present it to log in. Unset = OPEN
    // (anyone who connects gets full access) — fine for a loopback dev server, loud otherwise.
    let token = std::env::var("SCYLLA_RPC_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    // Cap concurrent connections so a flood can't spawn unbounded tasks (a DoS bound). Over the cap,
    // the surplus connection is accepted then immediately dropped.
    let max_conn: usize = std::env::var("SCYLLA_RPC_MAX_CONN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64)
        .max(1);
    // A connection that doesn't authenticate within this window is dropped (a slow-loris bound, so a
    // silent connection can't squat a slot — otherwise the cap above is trivially defeated).
    let handshake = std::time::Duration::from_secs(
        std::env::var("SCYLLA_RPC_HANDSHAKE_SEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
    );
    // Optional TLS (DD-035): with SCYLLA_RPC_TLS_CERT + SCYLLA_RPC_TLS_KEY (PEM), the wire is
    // encrypted so the token + the model never cross the network in the clear. Unset = plaintext.
    let acceptor = match (
        std::env::var("SCYLLA_RPC_TLS_CERT").ok(),
        std::env::var("SCYLLA_RPC_TLS_KEY").ok(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(&cert_path).unwrap_or_else(|e| {
                eprintln!("scylla-rpc-serve: cannot read TLS cert {cert_path}: {e}");
                std::process::exit(1);
            });
            let key = std::fs::read(&key_path).unwrap_or_else(|e| {
                eprintln!("scylla-rpc-serve: cannot read TLS key {key_path}: {e}");
                std::process::exit(1);
            });
            Some(tls_acceptor(&cert, &key).unwrap_or_else(|e| {
                eprintln!("scylla-rpc-serve: TLS config: {e}");
                std::process::exit(1);
            }))
        }
        _ => None,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let result: std::io::Result<()> = local.block_on(&rt, async move {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let shared: SharedSession = Rc::new(RefCell::new(session));
        let active = Rc::new(std::cell::Cell::new(0usize));
        let auth = if token.is_some() {
            "token-gated"
        } else {
            "OPEN (set SCYLLA_RPC_TOKEN to gate)"
        };
        let wire = if acceptor.is_some() { "TLS" } else { "plaintext" };
        eprintln!(
            "scylla-rpc-serve: {artifact} on {} — {auth}, {wire}, max {max_conn} conns (DD-002 capnp RPC; Ctrl-C to stop)",
            listener.local_addr()?
        );
        loop {
            let (stream, _peer) = listener.accept().await?;
            if active.get() >= max_conn {
                drop(stream); // at capacity — refuse the surplus connection
                continue;
            }
            let _ = stream.set_nodelay(true);
            active.set(active.get() + 1);
            let counter = active.clone();
            let (sess, tok, acc) = (shared.clone(), token.clone(), acceptor.clone());
            tokio::task::spawn_local(async move {
                match acc {
                    // Wrap the connection in TLS before the RPC handshake; a failed TLS handshake
                    // just drops the connection.
                    Some(a) => {
                        if let Ok(tls) = a.accept(stream).await {
                            serve_with_timeout(sess, tok, handshake, tls).await;
                        }
                    }
                    None => serve_with_timeout(sess, tok, handshake, stream).await,
                }
                counter.set(counter.get() - 1);
            });
        }
    });
    if let Err(e) = result {
        eprintln!("scylla-rpc-serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
