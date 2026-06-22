//! DD-002 RPC-shape spike: project `scylla_port::Session` over a Cap'n Proto RPC `interface`
//! and drive a PIPELINED navigation (`function(id) → callers → view`) to validate that the
//! port's shape survives the wire it was chosen for. Throwaway; not the production surface.
//!
//! What it proves: (1) the port projects cleanly to a capability-based interface — `function`/
//! `functions` return `Function` capabilities, `Function` answers `view`/`callers`, each backed
//! by the in-process `Session`; (2) promise-pipelining works — `session.function(gcd).callers()`
//! is issued on the un-resolved `function` capability (one round-trip), the navigation pattern
//! the port was designed around.

mod port_capnp {
    include!(concat!(env!("OUT_DIR"), "/port_capnp.rs"));
}

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;

use capnp::capability::FromClientHook;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use scylla_model::StableId;
use scylla_port::{Session, Zoom};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

type SharedSession = Rc<RefCell<Session>>;

fn function_client(session: &SharedSession, id: StableId) -> port_capnp::function::Client {
    capnp_rpc::new_client(FunctionImpl { session: session.clone(), id })
}

/// Server impl of `Session`, backed by the in-process client port.
struct SessionImpl {
    session: SharedSession,
}

impl port_capnp::session::Server for SessionImpl {
    fn function(
        self: capnp::capability::Rc<Self>,
        params: port_capnp::session::FunctionParams,
        mut results: port_capnp::session::FunctionResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let id = StableId(params.get()?.get_id());
            results.get().set_fn(function_client(&session, id));
            Ok(())
        }
    }

    fn functions(
        self: capnp::capability::Rc<Self>,
        _params: port_capnp::session::FunctionsParams,
        mut results: port_capnp::session::FunctionsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let ids: Vec<StableId> =
                session.borrow().program().functions.iter().map(|f| f.id).collect();
            let mut list = results.get().init_fns(ids.len() as u32);
            for (i, id) in ids.into_iter().enumerate() {
                list.set(i as u32, function_client(&session, id).into_client_hook());
            }
            Ok(())
        }
    }
}

/// Server impl of `Function` — a stable id + a handle to the in-process port.
struct FunctionImpl {
    session: SharedSession,
    id: StableId,
}

impl port_capnp::function::Server for FunctionImpl {
    fn view(
        self: capnp::capability::Rc<Self>,
        _params: port_capnp::function::ViewParams,
        mut results: port_capnp::function::ViewResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let v = session
                .borrow()
                .view(id, Zoom::Domain)
                .map_err(|e| capnp::Error::failed(e.to_string()))?;
            let mut r = results.get();
            r.set_id(id.0);
            r.set_name(v.name.as_str());
            r.set_summary(v.summary.as_str());
            r.set_addr(v.addr.unwrap_or(0));
            r.set_bb_count(v.bb_count.unwrap_or(0));
            Ok(())
        }
    }

    fn callers(
        self: capnp::capability::Rc<Self>,
        _params: port_capnp::function::CallersParams,
        mut results: port_capnp::function::CallersResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let ids = session.borrow().callers(id);
            let mut list = results.get().init_fns(ids.len() as u32);
            for (i, cid) in ids.into_iter().enumerate() {
                list.set(i as u32, function_client(&session, cid).into_client_hook());
            }
            Ok(())
        }
    }
}

/// Set up an in-memory two-party RPC, then drive a pipelined `function(gcd) → callers → view`
/// navigation. Returns the caller display names recovered over the wire.
async fn run_navigation(program: scylla_model::Program, gcd: StableId) -> capnp::Result<Vec<String>> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    // --- server ---
    let session: SharedSession = Rc::new(RefCell::new(Session::open(program)));
    let server: port_capnp::session::Client = capnp_rpc::new_client(SessionImpl { session });
    let (sr, sw) = tokio::io::split(server_io);
    let server_net = twoparty::VatNetwork::new(
        sr.compat(),
        sw.compat_write(),
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );
    let server_rpc = RpcSystem::new(Box::new(server_net), Some(server.clone().client));
    tokio::task::spawn_local(async move {
        let _ = server_rpc.await;
    });

    // --- client ---
    let (cr, cw) = tokio::io::split(client_io);
    let client_net = twoparty::VatNetwork::new(
        cr.compat(),
        cw.compat_write(),
        rpc_twoparty_capnp::Side::Client,
        Default::default(),
    );
    let mut client_rpc = RpcSystem::new(Box::new(client_net), None);
    let session: port_capnp::session::Client = client_rpc.bootstrap(rpc_twoparty_capnp::Side::Server);
    tokio::task::spawn_local(async move {
        let _ = client_rpc.await;
    });

    // --- PIPELINED navigation: callers() rides the un-resolved function() capability ---
    let mut req = session.function_request();
    req.get().set_id(gcd.0);
    let fn_promise = req.send();
    let func = fn_promise.pipeline.get_fn(); // capability derived from the un-resolved result
    let callers = func.callers_request().send().promise.await?;
    let fns = callers.get()?.get_fns()?;

    let mut names = Vec::new();
    for i in 0..fns.len() {
        let caller = fns.get(i)?;
        let v = caller.view_request().send().promise.await?;
        names.push(v.get()?.get_name()?.to_str()?.to_string());
    }
    names.sort();

    // Also exercise the list-all projection — same capability pattern as `callers`.
    let all = session.functions_request().send().promise.await?;
    let total = all.get()?.get_fns()?.len();
    println!("  (list-all: session.functions() returned {total} Function caps over RPC)");

    Ok(names)
}

const MATHLIB: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

fn load() -> (scylla_model::Program, StableId, Vec<String>) {
    let program = scylla_ingest::snapshot_to_program(MATHLIB).expect("snapshot parses");
    let gcd = program.functions.iter().find(|f| f.name == "gcd").expect("gcd present").id;
    // In-process truth: gcd's callers, by display name (what the RPC should reproduce).
    let session = Session::open(program.clone());
    let mut want: Vec<String> = session
        .callers(gcd)
        .into_iter()
        .filter_map(|id| program.functions.iter().find(|f| f.id == id).map(|f| f.name.clone()))
        .collect();
    want.sort();
    (program, gcd, want)
}

fn drive() -> capnp::Result<(Vec<String>, Vec<String>)> {
    let (program, gcd, want) = load();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    let got = local.block_on(&rt, run_navigation(program, gcd))?;
    Ok((got, want))
}

fn main() -> capnp::Result<()> {
    let (got, want) = drive()?;
    println!("DD-002 RPC-shape spike — gcd's callers over a Cap'n Proto RPC wire:");
    println!("  in-process port : {want:?}");
    println!("  over capnp RPC  : {got:?}");
    assert_eq!(got, want, "RPC navigation must reproduce the in-process port");
    println!("  MATCH — the port projects faithfully, and function(gcd).callers() pipelined.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_navigation_reproduces_the_in_process_port() {
        let (got, want) = drive().expect("rpc navigation runs");
        assert_eq!(got, want);
        assert!(want.contains(&"main".to_string()), "gcd is called by main");
    }
}
