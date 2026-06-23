//! `scylla-rpc-connect <host:port> <command>` — drive a REMOTE Scylla model over the DD-002 Cap'n
//! Proto RPC wire. This is the **remote head**: a consumer not co-located with the core, navigating
//! the client port by promise-pipelining (`function(id).callers().view()` is one round-trip).
//!
//!   scylla-rpc-connect <host:port> info
//!   scylla-rpc-connect <host:port> functions
//!   scylla-rpc-connect <host:port> view <id> [intent|domain|detail]
//!   scylla-rpc-connect <host:port> callers <id>
//!   scylla-rpc-connect <host:port> diff <other.scylla>   # structural diff over the wire (DD-017)

use std::process::ExitCode;

use scylla_rpc::{connect, login, tls_connector};
use tokio_rustls::rustls::pki_types::ServerName;

const USAGE: &str = "usage: scylla-rpc-connect <host:port> \
     <info | functions | view <id> [zoom] | callers <id> | diff <other.scylla> | export <out.scylla>>";

fn zoom_byte(arg: Option<&String>) -> u8 {
    match arg.map(String::as_str) {
        Some("intent") => 0,
        Some("detail") => 2,
        _ => 1, // domain
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(addr) = args.first().cloned() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move { run(&addr, &args).await })
}

async fn run(addr: &str, args: &[String]) -> ExitCode {
    let cmd = args.get(1).map(String::as_str).unwrap_or("info");
    // The id-taking commands need a u64 second argument.
    let want_id = || -> Result<u64, ExitCode> {
        args.get(2)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                eprintln!("error: {cmd} needs an integer id\n{USAGE}");
                ExitCode::from(2)
            })
    };

    let tcp = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connecting to {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = tcp.set_nodelay(true);
    // Optional TLS: SCYLLA_RPC_TLS_CA points to the server's cert/CA to trust; SCYLLA_RPC_TLS_SNI is
    // the name to verify it against (default "localhost"). Unset = plaintext.
    let (auth, rpc) = match std::env::var("SCYLLA_RPC_TLS_CA").ok() {
        Some(ca_path) => {
            let ca = match std::fs::read(&ca_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: reading TLS CA {ca_path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let connector = match tls_connector(&ca) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: TLS config: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let sni =
                std::env::var("SCYLLA_RPC_TLS_SNI").unwrap_or_else(|_| "localhost".to_string());
            let server_name = match ServerName::try_from(sni) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("error: bad TLS server name: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match connector.connect(server_name, tcp).await {
                Ok(tls) => connect(tls),
                Err(e) => {
                    eprintln!("error: TLS handshake: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => connect(tcp),
    };
    tokio::task::spawn_local(async move {
        let _ = rpc.await;
    });
    // Authenticate (DD-035) — token from SCYLLA_RPC_TOKEN, empty for an open server.
    let token = std::env::var("SCYLLA_RPC_TOKEN").unwrap_or_default();
    let session = match login(&auth, &token).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: login failed ({e}) — set SCYLLA_RPC_TOKEN to the server's token");
            return ExitCode::FAILURE;
        }
    };

    let result: capnp::Result<()> = async {
        match cmd {
            "info" => {
                let info = session.info_request().send().promise.await?;
                let i = info.get()?;
                println!("name:      {}", i.get_name()?.to_str()?);
                println!("language:  {}", i.get_language()?.to_str()?);
                println!("functions: {}", i.get_functions());
            }
            "functions" => {
                let all = session.functions_request().send().promise.await?;
                let fns = all.get()?.get_fns()?;
                let mut rows = Vec::new();
                for k in 0..fns.len() {
                    let v = fns.get(k)?.view_request().send().promise.await?;
                    let v = v.get()?;
                    rows.push((v.get_id(), v.get_name()?.to_str()?.to_string()));
                }
                rows.sort_by(|a, b| a.1.cmp(&b.1));
                for (id, name) in rows {
                    println!("{id}\t{name}");
                }
            }
            "view" => {
                let id = want_id().map_err(|_| capnp::Error::failed("bad id".into()))?;
                let zoom = zoom_byte(args.get(3));
                let mut req = session.function_request();
                req.get().set_id(id);
                let func = req.send().pipeline.get_fn();
                let mut vr = func.view_request();
                vr.get().set_zoom(zoom);
                let v = vr.send().promise.await?;
                let v = v.get()?;
                println!("name:    {}", v.get_name()?.to_str()?);
                println!("summary: {}", v.get_summary()?.to_str()?);
                println!("address: 0x{:x}", v.get_addr());
                println!("blocks:  {}", v.get_bb_count());
            }
            "callers" => {
                let id = want_id().map_err(|_| capnp::Error::failed("bad id".into()))?;
                // PIPELINED: callers() rides the un-resolved function() result — one round-trip.
                let mut req = session.function_request();
                req.get().set_id(id);
                let func = req.send().pipeline.get_fn();
                let callers = func.callers_request().send().promise.await?;
                let fns = callers.get()?.get_fns()?;
                let mut names = Vec::new();
                for k in 0..fns.len() {
                    let v = fns.get(k)?.view_request().send().promise.await?;
                    names.push(v.get()?.get_name()?.to_str()?.to_string());
                }
                names.sort();
                for n in names {
                    println!("{n}");
                }
            }
            "diff" => {
                let Some(other) = args.get(2) else {
                    eprintln!("error: diff needs <other.scylla>\n{USAGE}");
                    return Err(capnp::Error::failed("usage".into()));
                };
                // The CLIENT reads the comparison artifact and ships the bytes — the server never
                // touches the client's filesystem.
                let bytes = std::fs::read(other)
                    .map_err(|e| capnp::Error::failed(format!("reading {other}: {e}")))?;
                let mut req = session.diff_request();
                req.get().set_artifact(&bytes);
                let resp = req.send().promise.await?;
                let d = resp.get()?;
                let (renamed, modified) = (d.get_renamed()?, d.get_modified()?);
                let (added, removed) = (d.get_added()?, d.get_removed()?);
                println!(
                    "{} unchanged · {} renamed · {} modified · {} added · {} removed",
                    d.get_matched(),
                    renamed.len(),
                    modified.len(),
                    added.len(),
                    removed.len()
                );
                for i in 0..renamed.len() {
                    let p = renamed.get(i);
                    println!(
                        "renamed: {} -> {}",
                        p.get_here()?.to_str()?,
                        p.get_there()?.to_str()?
                    );
                }
                for i in 0..modified.len() {
                    let p = modified.get(i);
                    let (h, t) = (p.get_here()?.to_str()?, p.get_there()?.to_str()?);
                    if h == t {
                        println!("modified: {h}");
                    } else {
                        println!("modified: {h} -> {t}");
                    }
                }
                for i in 0..added.len() {
                    println!("added: {}", added.get(i)?.to_str()?);
                }
                for i in 0..removed.len() {
                    println!("removed: {}", removed.get(i)?.to_str()?);
                }
            }
            "export" => {
                let Some(out) = args.get(2) else {
                    eprintln!("error: export needs <out.scylla>\n{USAGE}");
                    return Err(capnp::Error::failed("usage".into()));
                };
                // Pull the served model (annotations included) down to a local .scylla (DD-026).
                let resp = session.export_request().send().promise.await?;
                let bytes = resp.get()?.get_artifact()?;
                std::fs::write(out, bytes)
                    .map_err(|e| capnp::Error::failed(format!("writing {out}: {e}")))?;
                println!("exported {} bytes -> {out}", bytes.len());
            }
            other => {
                eprintln!("error: unknown command {other:?}\n{USAGE}");
                return Err(capnp::Error::failed("usage".into()));
            }
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
