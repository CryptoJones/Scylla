//! `scylla-rpc-connect <host:port> <command>` — drive a REMOTE Scylla model over the DD-002 Cap'n
//! Proto RPC wire. This is the **remote head**: a consumer not co-located with the core, navigating
//! the client port by promise-pipelining (`function(id).callers().view()` is one round-trip).
//!
//!   scylla-rpc-connect <host:port> info
//!   scylla-rpc-connect <host:port> functions
//!   scylla-rpc-connect <host:port> view <id> [intent|domain|detail]
//!   scylla-rpc-connect <host:port> callers <id>

use std::process::ExitCode;

use scylla_rpc::connect;

const USAGE: &str =
    "usage: scylla-rpc-connect <host:port> <info | functions | view <id> [zoom] | callers <id>>";

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

    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connecting to {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = stream.set_nodelay(true);
    let (session, rpc) = connect(stream);
    tokio::task::spawn_local(async move {
        let _ = rpc.await;
    });

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
