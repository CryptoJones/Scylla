//! The GraphQL schema for the `scylla-graphql` head (DD-017): the client port projected as one
//! typed query graph. Queries READ (`info`/`functions`/`search`/`function`/`callers`/`diff`/
//! `export`); mutations WRITE durable user facts (`rename`/`retype`/`comment`, DD-005). Every
//! resolver is a thin projection of `scylla_port::Session` — the body — so the graph carries no
//! domain logic of its own; the conformance test pins each field to the port, verb-for-verb. If a
//! resolver ever computes something the port doesn't, that's a bug, not a feature.

use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use juniper::{
    graphql_object, EmptySubscription, FieldError, FieldResult, GraphQLEnum, GraphQLObject,
    RootNode, Value,
};
use scylla_model::{FactKind, Program, StableId};
use scylla_port::{PortError, Session, Zoom as PortZoom};

/// The execution context: the one resident session, behind a `Mutex` so mutations can annotate it
/// through the shared `&Context` juniper hands every resolver. The `Mutex` is NOT a concurrency
/// claim — the `tiny_http` loop is single-threaded, so it is always uncontended — it is a *type*
/// requirement: juniper's `#[graphql_object]` macro generates an async resolution path whose
/// futures must be `Send`, which forces `Context: Sync`, and a bare `RefCell` is `!Sync`. A `Mutex`
/// is the minimal `Sync` interior-mutability that satisfies the bound. (The HTTP head sidesteps all
/// of this by owning `&mut session` directly; a GraphQL resolver never gets `&mut`.)
pub struct Context {
    pub session: Mutex<Session>,
}
impl juniper::Context for Context {}

impl Context {
    pub fn new(session: Session) -> Self {
        Context {
            session: Mutex::new(session),
        }
    }
}

/// Semantic-zoom altitude (DD-020), mirrored from the port so a client picks how much detail it
/// pays for. `None` from a caller means `DOMAIN`, the same default every other head applies.
#[derive(Clone, Copy, Debug, GraphQLEnum)]
pub enum Zoom {
    /// Coarsest: identity + a one-line summary, nothing else.
    Intent,
    /// Default: the domain vocabulary (address, basic-block count, callees, callers).
    Domain,
    /// Finest: everything the v0 model holds (adds byte size).
    Detail,
}

fn port_zoom(z: Option<Zoom>) -> PortZoom {
    match z.unwrap_or(Zoom::Domain) {
        Zoom::Intent => PortZoom::Intent,
        Zoom::Domain => PortZoom::Domain,
        Zoom::Detail => PortZoom::Detail,
    }
}

/// Program identity + how many functions it holds.
#[derive(GraphQLObject)]
pub struct Info {
    pub name: String,
    pub language: String,
    pub functions: i32,
}

/// A function at list altitude — identity + one-line summary, the shape `functions`/`search` return.
#[derive(GraphQLObject)]
pub struct FunctionSummary {
    /// The synthetic stable id (DD-004) as a decimal string — it is a `u64`, wider than a GraphQL
    /// `Int` (which is 32-bit), so it crosses the wire as a string and never silently truncates.
    pub id: String,
    pub name: String,
    pub summary: String,
}

/// A caller reference — id + display name (the user rename wins over the engine symbol, DD-005).
#[derive(GraphQLObject)]
pub struct Caller {
    pub id: String,
    pub name: String,
}

/// One function's full view at a chosen zoom. The `Option` fields are present-or-absent by
/// altitude, exactly as the port populates them — a GraphQL client sees the same null where a
/// coarser zoom withheld a field.
#[derive(GraphQLObject)]
pub struct FunctionDetail {
    pub id: String,
    pub name: String,
    pub summary: String,
    /// Entry address as a decimal string (`u64`), populated at `DOMAIN`+.
    pub addr: Option<String>,
    /// Basic-block count, populated at `DOMAIN`+.
    pub bb_count: Option<i32>,
    /// Byte size as a decimal string (`u64`), populated at `DETAIL` only.
    pub size: Option<String>,
    pub callees: Option<Vec<String>>,
    pub callers: Option<Vec<String>>,
    /// The user comment attached to this function (DD-005 durable fact), if any.
    pub comment: Option<String>,
    /// The user-assigned type (DD-005), if any.
    pub user_type: Option<String>,
}

/// A matched / renamed / modified function pair: `from` is this model's name, `to` is the other's.
#[derive(GraphQLObject)]
pub struct Pair {
    pub from: String,
    pub to: String,
}

/// How many pairs a given ladder rung recovered (exact / propagation / anchor / bsim / fuzzy).
#[derive(GraphQLObject)]
pub struct MethodCount {
    pub method: String,
    pub count: i32,
}

/// Per-pair provenance: HOW a matched/modified function was recovered, and HOW STRONGLY.
#[derive(GraphQLObject)]
pub struct MatchConfidence {
    pub name: String,
    pub method: String,
    /// 0..=100 percent — `exact` and `propagation` are always 100; the soft rungs carry the actual
    /// threshold-clearing score.
    pub confidence: i32,
}

/// The structural binary-diff report (DD-017): re-identification by structural identity, with the
/// ladder-rung tally + per-pair confidence the other heads also surface.
#[derive(GraphQLObject)]
pub struct DiffReport {
    /// Pairs matched with the name unchanged.
    pub matched: i32,
    /// Pairs matched but renamed (`from` != `to`).
    pub renamed: Vec<Pair>,
    /// Pairs re-identified with a changed body (modified, never reported as remove+add).
    pub modified: Vec<Pair>,
    /// Functions present only in the other model.
    pub added: Vec<String>,
    /// Functions present only in this model.
    pub removed: Vec<String>,
    pub methods: Vec<MethodCount>,
    pub confidence: Vec<MatchConfidence>,
}

/// The acknowledgement an annotation mutation returns; failures surface as GraphQL `errors`, not
/// as `ok: false` (a rejected rename is an error, not a successful no-op).
#[derive(GraphQLObject)]
pub struct MutationResult {
    pub ok: bool,
    pub id: String,
}

fn ferr(msg: impl Into<String>) -> FieldError {
    FieldError::new(msg.into(), Value::null())
}

/// Parse a string id to a `StableId`, erroring (not nulling) on non-integer input — a malformed id
/// is a client mistake, distinct from a well-formed id that simply isn't present.
fn parse_id(id: &str) -> FieldResult<StableId> {
    id.parse::<u64>()
        .map(StableId)
        .map_err(|_| ferr("id must be an integer"))
}

/// The user comment attached to `id` (DD-005), if any.
fn comment_of(prog: &Program, id: StableId) -> Option<String> {
    prog.facts.iter().find_map(|f| match &f.kind {
        FactKind::Comment(c) if f.target == id => Some(c.clone()),
        _ => None,
    })
}

/// The user-assigned type for `id`, if any.
fn type_of(prog: &Program, id: StableId) -> Option<String> {
    prog.facts.iter().find_map(|f| match &f.kind {
        FactKind::Retype(t) if f.target == id => Some(t.clone()),
        _ => None,
    })
}

fn summary(f: &scylla_port::FunctionView) -> FunctionSummary {
    FunctionSummary {
        id: f.id.0.to_string(),
        name: f.name.clone(),
        summary: f.summary.clone(),
    }
}

/// The read graph.
pub struct Query;

#[graphql_object(context = Context)]
impl Query {
    /// Program identity + function count.
    fn info(context: &Context) -> Info {
        let s = context.session.lock().expect("session lock");
        let p = s.program();
        Info {
            name: p.name.clone(),
            language: p.language.clone(),
            functions: p.functions.len() as i32,
        }
    }

    /// Every function at the given zoom (default `DOMAIN`), sorted by name.
    fn functions(context: &Context, zoom: Option<Zoom>) -> Vec<FunctionSummary> {
        let s = context.session.lock().expect("session lock");
        let mut fns = s.functions(port_zoom(zoom));
        fns.sort_by(|a, b| a.name.cmp(&b.name));
        fns.iter().map(summary).collect()
    }

    /// Functions whose display name contains `query` (case-insensitive); empty `query` = all.
    fn search(context: &Context, query: String, zoom: Option<Zoom>) -> Vec<FunctionSummary> {
        let s = context.session.lock().expect("session lock");
        s.search(&query, port_zoom(zoom)).iter().map(summary).collect()
    }

    /// One function's view at `zoom` (default `DOMAIN`); `null` if no such id, error on a bad id.
    fn function(
        context: &Context,
        id: String,
        zoom: Option<Zoom>,
    ) -> FieldResult<Option<FunctionDetail>> {
        let sid = parse_id(&id)?;
        let s = context.session.lock().expect("session lock");
        match s.view(sid, port_zoom(zoom)) {
            Ok(v) => {
                let prog = s.program();
                Ok(Some(FunctionDetail {
                    id: v.id.0.to_string(),
                    name: v.name,
                    summary: v.summary,
                    addr: v.addr.map(|a| a.to_string()),
                    bb_count: v.bb_count.map(|b| b as i32),
                    size: v.size.map(|n| n.to_string()),
                    callees: v.callees,
                    callers: v.callers,
                    comment: comment_of(prog, sid),
                    user_type: type_of(prog, sid),
                }))
            }
            Err(PortError::NoSuchFunction(_)) => Ok(None),
            Err(e) => Err(ferr(e.to_string())),
        }
    }

    /// The functions that call `id`; errors if `id` is absent (an unknown target is a client error).
    fn callers(context: &Context, id: String) -> FieldResult<Vec<Caller>> {
        let sid = parse_id(&id)?;
        let s = context.session.lock().expect("session lock");
        let prog = s.program();
        if !prog.functions.iter().any(|f| f.id == sid) {
            return Err(ferr(format!("no function with id {}", sid.0)));
        }
        Ok(s
            .callers(sid)
            .into_iter()
            .map(|c| Caller {
                id: c.0.to_string(),
                name: prog.display_name(c).unwrap_or_default(),
            })
            .collect())
    }

    /// Structural binary-diff against another `.scylla` (base64-encoded body), DD-017.
    fn diff(context: &Context, artifact_base64: String) -> FieldResult<DiffReport> {
        let bytes = B64
            .decode(artifact_base64.as_bytes())
            .map_err(|e| ferr(format!("artifactBase64 is not valid base64: {e}")))?;
        let other = Session::from_artifact(&bytes).map_err(|e| ferr(format!("invalid .scylla: {e}")))?;
        let s = context.session.lock().expect("session lock");
        let d = s.diff(&other);
        let renamed: Vec<Pair> = d
            .matched
            .iter()
            .filter(|(a, b)| a != b)
            .map(|(a, b)| Pair {
                from: a.clone(),
                to: b.clone(),
            })
            .collect();
        let unchanged = d.matched.len() - renamed.len();
        let modified: Vec<Pair> = d
            .changed
            .iter()
            .map(|(a, b)| Pair {
                from: a.clone(),
                to: b.clone(),
            })
            .collect();
        let mut methods: Vec<MethodCount> = Vec::new();
        let mut confidence: Vec<MatchConfidence> = Vec::new();
        for (name, info) in &d.provenance {
            let rung = info.method.as_str();
            match methods.iter_mut().find(|m| m.method == rung) {
                Some(m) => m.count += 1,
                None => methods.push(MethodCount {
                    method: rung.to_string(),
                    count: 1,
                }),
            }
            confidence.push(MatchConfidence {
                name: name.clone(),
                method: rung.to_string(),
                confidence: info.confidence as i32,
            });
        }
        Ok(DiffReport {
            matched: unchanged as i32,
            renamed,
            modified,
            added: d.only_there.clone(),
            removed: d.only_here.clone(),
            methods,
            confidence,
        })
    }

    /// The resident model — INCLUDING annotations made this session — as a base64 `.scylla`, so a
    /// remote client can pull its work back out (in-memory facts otherwise die with the server).
    fn export(context: &Context) -> String {
        let s = context.session.lock().expect("session lock");
        B64.encode(s.to_artifact())
    }
}

/// The write graph: the three durable-fact verbs (DD-005). Each mutates the resident session in
/// place and is visible to the next query.
pub struct Mutation;

#[graphql_object(context = Context)]
impl Mutation {
    /// Rename a function; errors on a blank name (InvalidInput) or unknown id.
    fn rename(context: &Context, id: String, name: String) -> FieldResult<MutationResult> {
        annotate(context, &id, |s, sid| s.rename(sid, name.clone()))
    }

    /// Assign a user type (exposed as `newType` to dodge the `type` keyword); blank is rejected.
    fn retype(context: &Context, id: String, new_type: String) -> FieldResult<MutationResult> {
        annotate(context, &id, |s, sid| s.retype(sid, new_type.clone()))
    }

    /// Attach a comment; an empty string is valid and clears it (unlike rename/retype).
    fn comment(context: &Context, id: String, text: String) -> FieldResult<MutationResult> {
        annotate(context, &id, |s, sid| s.comment(sid, text.clone()))
    }
}

/// Shared spine of the three annotation verbs: resolve the id (error if unknown), apply the port
/// verb against the resident session (mapping a `PortError` to a GraphQL error). The mutation lands
/// on the session and shows up on the next read (DD-005).
fn annotate(
    context: &Context,
    id: &str,
    apply: impl FnOnce(&mut Session, StableId) -> Result<(), PortError>,
) -> FieldResult<MutationResult> {
    let sid = parse_id(id)?;
    let mut s = context.session.lock().expect("session lock");
    if !s.program().functions.iter().any(|f| f.id == sid) {
        return Err(ferr(format!("no function with id {}", sid.0)));
    }
    apply(&mut s, sid).map_err(|e| ferr(e.to_string()))?;
    Ok(MutationResult {
        ok: true,
        id: sid.0.to_string(),
    })
}

/// The schema type and its constructor — one `RootNode` over the read graph, the write graph, and
/// no subscriptions (nothing here is a stream).
pub type Schema = RootNode<'static, Query, Mutation, EmptySubscription<Context>>;

pub fn schema() -> Schema {
    Schema::new(Query, Mutation, EmptySubscription::new())
}
