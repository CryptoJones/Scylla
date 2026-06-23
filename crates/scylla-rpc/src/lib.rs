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

use scylla_rpc_capnp::{authenticator, function, session};

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

/// Wrap a loaded session as a `Session` capability (no auth — for embedding / tests).
pub fn session_server(session: SharedSession) -> session::Client {
    capnp_rpc::new_client(SessionImpl { session })
}

/// The bootstrap `Authenticator` capability: a client must `login(token)` to obtain the `Session`.
/// `token = None` runs OPEN (any login succeeds) — the server warns; `Some(t)` requires an exact
/// match (a wrong token is a `capnp::Error`, never a `Session`). Capability-based auth (DD-035): no
/// authority leaks until authentication.
pub fn auth_server(session: SharedSession, token: Option<String>) -> authenticator::Client {
    capnp_rpc::new_client(AuthImpl {
        session,
        token,
        authed: None,
    })
}

struct AuthImpl {
    session: SharedSession,
    token: Option<String>,
    /// Set `true` on a successful login — [`serve_with_timeout`] uses it to drop connections that
    /// never authenticate (a slow-loris bound).
    authed: Option<Rc<std::cell::Cell<bool>>>,
}

impl authenticator::Server for AuthImpl {
    fn login(
        self: capnp::capability::Rc<Self>,
        params: authenticator::LoginParams,
        mut results: authenticator::LoginResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let (session, expected, authed) = (
            self.session.clone(),
            self.token.clone(),
            self.authed.clone(),
        );
        async move {
            let presented = params.get()?.get_token()?.to_str()?;
            if let Some(t) = &expected {
                if presented != t.as_str() {
                    return Err(capnp::Error::failed(
                        "authentication failed: bad token".into(),
                    ));
                }
            }
            if let Some(flag) = &authed {
                flag.set(true);
            }
            results.get().set_session(session_server(session));
            Ok(())
        }
    }
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
            {
                // Match-confidence breakdown by ladder rung (DD-017), aggregated from provenance.
                let mut counts: std::collections::BTreeMap<&str, u32> =
                    std::collections::BTreeMap::new();
                for (_, m) in &d.provenance {
                    *counts.entry(m.as_str()).or_default() += 1;
                }
                let mut list = r.reborrow().init_methods(counts.len() as u32);
                for (i, (method, count)) in counts.iter().enumerate() {
                    let mut mc = list.reborrow().get(i as u32);
                    mc.set_method(method);
                    mc.set_count(*count);
                }
            }
            Ok(())
        }
    }

    fn export(
        self: capnp::capability::Rc<Self>,
        _params: session::ExportParams,
        mut results: session::ExportResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let session = self.session.clone();
        async move {
            // Serialize the served model — annotations included — and ship the bytes (DD-026).
            let bytes = session.borrow().to_artifact();
            results.get().set_artifact(&bytes);
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

/// Serve a loaded `session` over one bidirectional byte stream (a TCP connection, a duplex pipe),
/// gated by `token` (`None` = open, with a server-side warning). The bootstrap is an `Authenticator`
/// — a client must `login` before it gets the `Session`. Returns the server-side `RpcSystem` (a
/// `Future`) — drive it with `.await` on a `LocalSet`; it resolves when the peer disconnects.
pub fn serve_connection<T>(
    session: SharedSession,
    token: Option<String>,
    io: T,
) -> RpcSystem<rpc_twoparty_capnp::Side>
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
    let auth = auth_server(session, token);
    RpcSystem::new(Box::new(net), Some(auth.client))
}

/// Serve one connection but DROP it if the client hasn't authenticated within `handshake` — a
/// slow-loris bound, so a silent connection can't hold a slot forever (which would defeat the
/// `serve` binary's connection cap). On a timely login the session runs to completion as usual.
/// Run on a `LocalSet`. The caller's per-connection slot frees when this returns (either path).
pub async fn serve_with_timeout<T>(
    session: SharedSession,
    token: Option<String>,
    handshake: std::time::Duration,
    io: T,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let authed = Rc::new(std::cell::Cell::new(false));
    let (r, w) = tokio::io::split(io);
    let net = twoparty::VatNetwork::new(
        r.compat(),
        w.compat_write(),
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );
    let auth: authenticator::Client = capnp_rpc::new_client(AuthImpl {
        session,
        token,
        authed: Some(authed.clone()),
    });
    let rpc = RpcSystem::new(Box::new(net), Some(auth.client));
    let task = tokio::task::spawn_local(rpc);
    // A watchdog aborts the connection iff it hasn't authenticated by the deadline. The connection's
    // OWN completion (a clean session end, a disconnect, an error) frees the slot promptly — we await
    // the task directly rather than always sleeping the full window.
    let abort = task.abort_handle();
    let watchdog = tokio::task::spawn_local(async move {
        tokio::time::sleep(handshake).await;
        if !authed.get() {
            abort.abort();
        }
    });
    let _ = task.await;
    watchdog.abort();
}

/// Connect to a served endpoint over one byte stream. Returns the bootstrapped `Authenticator`
/// capability plus the client-side `RpcSystem` (a `Future`) — spawn the system on a `LocalSet`,
/// then [`login`] to obtain the `Session`.
pub fn connect<T>(io: T) -> (authenticator::Client, RpcSystem<rpc_twoparty_capnp::Side>)
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
    let auth: authenticator::Client = rpc.bootstrap(rpc_twoparty_capnp::Side::Server);
    (auth, rpc)
}

/// Build a TLS acceptor (server side) from PEM cert + key bytes — so the auth token and the model
/// don't cross the wire in the clear (DD-035). `ring` crypto provider. Errors describe the problem.
pub fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<tokio_rustls::TlsAcceptor, String> {
    use std::sync::Arc;
    use tokio_rustls::rustls;
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("reading cert: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate in the cert PEM".into());
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("reading key: {e}"))?
        .ok_or("no private key in the key PEM")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Build a TLS connector (client side) trusting the CA / self-signed cert in `ca_pem`.
pub fn tls_connector(ca_pem: &[u8]) -> Result<tokio_rustls::TlsConnector, String> {
    use std::sync::Arc;
    use tokio_rustls::rustls;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
        roots
            .add(cert.map_err(|e| format!("reading CA: {e}"))?)
            .map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Authenticate to obtain the `Session` capability. A wrong token comes back as a `capnp::Error`.
pub async fn login(auth: &authenticator::Client, token: &str) -> capnp::Result<session::Client> {
    let mut req = auth.login_request();
    req.get().set_token(token);
    let resp = req.send().promise.await?;
    resp.get()?.get_session()
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
            let server = serve_connection(session, None, server_io); // open mode for these tests
            tokio::task::spawn_local(async move {
                let _ = server.await;
            });
            let (auth, client_rpc) = connect(client_io);
            tokio::task::spawn_local(async move {
                let _ = client_rpc.await;
            });
            let client = login(&auth, "").await.expect("login (open mode)");
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
    fn auth_gates_access_with_a_token() {
        // A token-gated server hands out the Session only on the right token (DD-035): a wrong token
        // is a capnp::Error (no authority leaks), the right one yields a working Session.
        let prog = program();
        let n = prog.functions.len() as u32;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        let (wrong_denied, right_works) = local.block_on(&rt, async move {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let session: SharedSession = Rc::new(RefCell::new(Session::open(prog)));
            let server = serve_connection(session, Some("s3cret".to_string()), server_io);
            tokio::task::spawn_local(async move {
                let _ = server.await;
            });
            let (auth, client_rpc) = connect(client_io);
            tokio::task::spawn_local(async move {
                let _ = client_rpc.await;
            });
            let wrong_denied = login(&auth, "nope").await.is_err();
            let right_works = match login(&auth, "s3cret").await {
                Ok(sess) => {
                    let info = sess.info_request().send().promise.await.unwrap();
                    info.get().unwrap().get_functions() == n
                }
                Err(_) => false,
            };
            (wrong_denied, right_works)
        });
        assert!(wrong_denied, "a wrong token must NOT yield a Session");
        assert!(right_works, "the right token yields a working Session");
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

    #[test]
    fn export_over_the_wire_round_trips_annotations() {
        // Rename gcd over the wire, then `export` the served model — the bytes reload into a Session
        // with the rename intact (DD-026), so a remote analyst can pull their work down.
        let prog = program();
        let gcd = id_of(&prog, "gcd");
        let bytes = with_rpc(prog, move |session| async move {
            let mut req = session.function_request();
            req.get().set_id(gcd.0);
            let func = req.send().pipeline.get_fn();
            let mut rn = func.rename_request();
            rn.get().set_name("euclid_gcd");
            rn.send().promise.await.unwrap();

            let resp = session.export_request().send().promise.await.unwrap();
            resp.get().unwrap().get_artifact().unwrap().to_vec()
        });
        let reloaded = Session::from_artifact(&bytes).expect("exported bytes are a valid .scylla");
        assert!(
            reloaded
                .functions(scylla_port::Zoom::Domain)
                .iter()
                .any(|f| f.name == "euclid_gcd"),
            "the rename survived export → reload over the wire"
        );
    }
}
