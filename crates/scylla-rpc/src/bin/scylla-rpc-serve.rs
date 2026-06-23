//! `scylla-rpc-serve <artifact.scylla> [host:port]` — serve a loaded `.scylla` model over the
//! DD-002 Cap'n Proto promise-pipelining RPC interface to **remote** clients (the deferred remote
//! head, now real). Default `127.0.0.1:9000`. One resident session; each TCP connection gets its
//! own RPC system over the SAME session (single-threaded `LocalSet` — capnp-rpc capabilities are
//! `!Send`). Read-only-ish: annotations mutate the in-memory session, not the on-disk artifact.

use std::cell::RefCell;
use std::process::ExitCode;
use std::rc::Rc;

use scylla_port::Session;
use scylla_rpc::{serve_connection, SharedSession};

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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let result: std::io::Result<()> = local.block_on(&rt, async move {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let shared: SharedSession = Rc::new(RefCell::new(session));
        let auth = if token.is_some() {
            "token-gated"
        } else {
            "OPEN (set SCYLLA_RPC_TOKEN to gate)"
        };
        eprintln!(
            "scylla-rpc-serve: {artifact} on {} — {auth} (DD-002 capnp RPC; Ctrl-C to stop)",
            listener.local_addr()?
        );
        loop {
            let (stream, _peer) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let rpc = serve_connection(shared.clone(), token.clone(), stream);
            tokio::task::spawn_local(async move {
                let _ = rpc.await;
            });
        }
    });
    if let Err(e) = result {
        eprintln!("scylla-rpc-serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
