//! DD-002 — the **remote head's seam**: `scylla_port::Session` projected over a Cap'n Proto
//! promise-pipelining RPC `interface`. The same client port the in-process heads (mcp/wasm/serve/
//! cli) drive, now reachable by a head that is **not co-located with the core** — the precondition
//! the DD-002 deferral was waiting on.
//!
//! A lookup returns a **capability** (`Function`), not data, so a client can call methods on the
//! not-yet-resolved capability: `session.function(id).callers().view()` collapses to ONE network
//! round-trip — the navigation pattern the port (and the Cap'n Proto choice) was designed around.
//! Validated end-to-end by `spike/rpc-shape` (GO); this is the production crate that seed grew into.
//!
//! The server is a thin **async wrapper** whose method bodies make **synchronous** port calls (the
//! sync/async boundary stays clean — DD-009). capnp-rpc capabilities are `!Send` (`Rc`), so the
//! server + client RPC systems run on a single-threaded `tokio::task::LocalSet`.

#![allow(clippy::needless_lifetimes)]

/// The generated Cap'n Proto RPC bindings (`schema/scylla_rpc.capnp`).
pub mod scylla_rpc_capnp {
    include!(concat!(env!("OUT_DIR"), "/scylla_rpc_capnp.rs"));
}

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;

use capnp::capability::FromClientHook;
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
use scylla_model::StableId;
use scylla_port::{Session, Zoom};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use scylla_rpc_capnp::{function, session};

/// A loaded port session, shared between the RPC capabilities serving it. `!Send` (`Rc`) — the RPC
/// runs on a `LocalSet`, matching capnp-rpc's single-threaded capability model.
pub type SharedSession = Rc<RefCell<Session>>;

/// DD-020 zoom altitude from the wire byte (0 = intent, 1 = domain, 2 = detail; default domain).
fn zoom_of(level: u8) -> Zoom {
    match level {
        0 => Zoom::Intent,
        2 => Zoom::Detail,
        _ => Zoom::Domain,
    }
}

fn function_client(session: &SharedSession, id: StableId) -> function::Client {
    capnp_rpc::new_client(FunctionImpl {
        session: session.clone(),
        id,
    })
}

/// Wrap a loaded session as the bootstrap `Session` capability a client connects to.
pub fn session_server(session: SharedSession) -> session::Client {
    capnp_rpc::new_client(SessionImpl { session })
}

/// Server impl of `Session`, backed by the in-process client port.
struct SessionImpl {
    session: SharedSession,
}

impl session::Server for SessionImpl {
    fn info(
        self: capnp::capability::Rc<Self>,
        _params: session::InfoParams,
        mut results: session::InfoResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let s = session.borrow();
            let p = s.program();
            let mut r = results.get();
            r.set_name(p.name.as_str());
            r.set_language(p.language.as_str());
            r.set_functions(p.functions.len() as u32);
            Ok(())
        }
    }

    fn functions(
        self: capnp::capability::Rc<Self>,
        _params: session::FunctionsParams,
        mut results: session::FunctionsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let ids: Vec<StableId> = session
                .borrow()
                .program()
                .functions
                .iter()
                .map(|f| f.id)
                .collect();
            let mut list = results.get().init_fns(ids.len() as u32);
            for (i, id) in ids.into_iter().enumerate() {
                list.set(i as u32, function_client(&session, id).into_client_hook());
            }
            Ok(())
        }
    }

    fn function(
        self: capnp::capability::Rc<Self>,
        params: session::FunctionParams,
        mut results: session::FunctionResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let id = StableId(params.get()?.get_id());
            results.get().set_fn(function_client(&session, id));
            Ok(())
        }
    }

    fn diff(
        self: capnp::capability::Rc<Self>,
        params: session::DiffParams,
        mut results: session::DiffResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            let bytes = params.get()?.get_artifact()?;
            let other =
                Session::from_artifact(bytes).map_err(|e| capnp::Error::failed(e.to_string()))?;
            let d = session.borrow().diff(&other);
            let renamed: Vec<(String, String)> =
                d.matched.iter().filter(|(a, b)| a != b).cloned().collect();
            let unchanged = (d.matched.len() - renamed.len()) as u32;
            let mut r = results.get();
            r.set_matched(unchanged);
            {
                let mut list = r.reborrow().init_renamed(renamed.len() as u32);
                for (i, (a, b)) in renamed.iter().enumerate() {
                    let mut p = list.reborrow().get(i as u32);
                    p.set_here(a.as_str());
                    p.set_there(b.as_str());
                }
            }
            {
                let mut list = r.reborrow().init_modified(d.changed.len() as u32);
                for (i, (a, b)) in d.changed.iter().enumerate() {
                    let mut p = list.reborrow().get(i as u32);
                    p.set_here(a.as_str());
                    p.set_there(b.as_str());
                }
            }
            {
                let mut list = r.reborrow().init_added(d.only_there.len() as u32);
                for (i, n) in d.only_there.iter().enumerate() {
                    list.set(i as u32, n.as_str());
                }
            }
            {
                let mut list = r.reborrow().init_removed(d.only_here.len() as u32);
                for (i, n) in d.only_here.iter().enumerate() {
                    list.set(i as u32, n.as_str());
                }
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

impl function::Server for FunctionImpl {
    fn view(
        self: capnp::capability::Rc<Self>,
        params: function::ViewParams,
        mut results: function::ViewResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let zoom = zoom_of(params.get()?.get_zoom());
            let v = session
                .borrow()
                .view(id, zoom)
                .map_err(|e| capnp::Error::failed(e.to_string()))?;
            let mut r = results.get();
            r.set_id(id.0);
            r.set_name(v.name.as_str());
            r.set_summary(v.summary.as_str());
            r.set_addr(v.addr.unwrap_or(0));
            r.set_bb_count(v.bb_count.unwrap_or(0));
            r.set_size(v.size.unwrap_or(0));
            Ok(())
        }
    }

    fn callers(
        self: capnp::capability::Rc<Self>,
        _params: function::CallersParams,
        mut results: function::CallersResults,
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

    fn rename(
        self: capnp::capability::Rc<Self>,
        params: function::RenameParams,
        _results: function::RenameResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let name = params.get()?.get_name()?.to_str()?.to_string();
            session
                .borrow_mut()
                .rename(id, name)
                .map_err(|e| capnp::Error::failed(e.to_string()))
        }
    }

    fn retype(
        self: capnp::capability::Rc<Self>,
        params: function::RetypeParams,
        _results: function::RetypeResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let ty = params.get()?.get_type()?.to_str()?.to_string();
            session
                .borrow_mut()
                .retype(id, ty)
                .map_err(|e| capnp::Error::failed(e.to_string()))
        }
    }

    fn comment(
        self: capnp::capability::Rc<Self>,
        params: function::CommentParams,
        _results: function::CommentResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, id) = (self.session.clone(), self.id);
        async move {
            let text = params.get()?.get_text()?.to_str()?.to_string();
            session
                .borrow_mut()
                .comment(id, text)
                .map_err(|e| capnp::Error::failed(e.to_string()))
        }
    }
}

/// Serve a loaded `session` over one bidirectional byte stream (a TCP connection, a duplex pipe).
/// Returns the server-side `RpcSystem` (a `Future`) — drive it with `.await` on a `LocalSet` (it
/// resolves when the peer disconnects). One call per connection.
pub fn serve_connection<T>(session: SharedSession, io: T) -> RpcSystem<rpc_twoparty_capnp::Side>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let (r, w) = tokio::io::split(io);
    let net = twoparty::VatNetwork::new(
        r.compat(),
        w.compat_write(),
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );
    let client = session_server(session);
    RpcSystem::new(Box::new(net), Some(client.client))
}

/// Connect a client to a served session over one byte stream. Returns the bootstrapped `Session`
/// capability plus the client-side `RpcSystem` (a `Future`) — spawn the system on a `LocalSet`,
/// then drive the port through the capability.
pub fn connect<T>(io: T) -> (session::Client, RpcSystem<rpc_twoparty_capnp::Side>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let (r, w) = tokio::io::split(io);
    let net = twoparty::VatNetwork::new(
        r.compat(),
        w.compat_write(),
        rpc_twoparty_capnp::Side::Client,
        Default::default(),
    );
    let mut rpc = RpcSystem::new(Box::new(net), None);
    let client: session::Client = rpc.bootstrap(rpc_twoparty_capnp::Side::Server);
    (client, rpc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATHLIB: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

    fn program() -> scylla_model::Program {
        scylla_ingest::snapshot_to_program(MATHLIB).expect("snapshot parses")
    }

    fn id_of(p: &scylla_model::Program, name: &str) -> StableId {
        p.functions
            .iter()
            .find(|f| f.name == name)
            .expect("function present")
            .id
    }

    /// Spin up an in-memory two-party RPC over a duplex pipe, run `f` against the client `Session`,
    /// and return its result — the same wiring the network binary uses, with `tokio::io::duplex`
    /// standing in for a TCP connection.
    fn with_rpc<F, Fut, R>(prog: scylla_model::Program, f: F) -> R
    where
        F: FnOnce(session::Client) -> Fut + 'static,
        Fut: Future<Output = R>,
        R: 'static,
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let session: SharedSession = Rc::new(RefCell::new(Session::open(prog)));
            let server = serve_connection(session, server_io);
            tokio::task::spawn_local(async move {
                let _ = server.await;
            });
            let (client, client_rpc) = connect(client_io);
            tokio::task::spawn_local(async move {
                let _ = client_rpc.await;
            });
            f(client).await
        })
    }

    #[test]
    fn pipelined_navigation_reproduces_the_in_process_port() {
        let prog = program();
        let gcd = id_of(&prog, "gcd");
        let names = with_rpc(prog, move |session| async move {
            // PIPELINED: callers() rides the un-resolved function() result — one round-trip.
            let mut req = session.function_request();
            req.get().set_id(gcd.0);
            let func = req.send().pipeline.get_fn();
            let callers = func.callers_request().send().promise.await.unwrap();
            let fns = callers.get().unwrap().get_fns().unwrap();
            let mut names = Vec::new();
            for i in 0..fns.len() {
                let caller = fns.get(i).unwrap();
                let v = caller.view_request().send().promise.await.unwrap();
                names.push(
                    v.get()
                        .unwrap()
                        .get_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
            }
            names.sort();
            names
        });
        assert_eq!(
            names,
            vec!["main".to_string()],
            "gcd's callers, over the wire"
        );
    }

    #[test]
    fn info_and_functions_project_over_the_wire() {
        let prog = program();
        let n = prog.functions.len() as u32;
        let (count, listed) = with_rpc(prog, move |session| async move {
            let info = session.info_request().send().promise.await.unwrap();
            let count = info.get().unwrap().get_functions();
            let all = session.functions_request().send().promise.await.unwrap();
            let listed = all.get().unwrap().get_fns().unwrap().len();
            (count, listed)
        });
        assert_eq!(count, n, "info() reports the function count");
        assert_eq!(listed, n, "functions() returns one capability per function");
    }

    #[test]
    fn rename_over_the_wire_mutates_the_served_session() {
        let prog = program();
        let gcd = id_of(&prog, "gcd");
        let (renamed, blank_rejected) = with_rpc(prog, move |session| async move {
            let mut req = session.function_request();
            req.get().set_id(gcd.0);
            let func = req.send().pipeline.get_fn();
            // a rename round-trip
            let mut rn = func.rename_request();
            rn.get().set_name("euclid_gcd");
            rn.send().promise.await.unwrap();
            let v = func.view_request().send().promise.await.unwrap();
            let renamed = v
                .get()
                .unwrap()
                .get_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            // DD-021: a blank name is rejected -> a capnp::Error over the wire
            let mut bad = func.rename_request();
            bad.get().set_name("");
            let blank_rejected = bad.send().promise.await.is_err();
            (renamed, blank_rejected)
        });
        assert_eq!(
            renamed, "euclid_gcd",
            "the rename mutated the served session"
        );
        assert!(
            blank_rejected,
            "a blank name maps to a capnp::Error (DD-021)"
        );
    }
}
