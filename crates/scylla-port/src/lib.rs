//! The **client port** (DD-017): a data-centric, model-primary command surface a consumer
//! (a head) drives. Consumers see the *model* — a function, its decompilation-to-be, its
//! callers — never engine operations.
//!
//! - **DD-020 semantic zoom:** every view carries a [`Zoom`] altitude. The domain vocabulary
//!   is the default; `Intent` is coarser (a one-line summary), `Detail` is the fine escape
//!   hatch. The consumer/agent composes higher intent; the port never bakes it in.
//! - **DD-005 annotation:** `rename`/`retype`/`comment` write durable user facts.
//! - **DD-021 typed errors:** a small taxonomy a head can translate faithfully.
//!
//! This is the *consume* side over a loaded model. The engine-driven verbs (`import`,
//! `analyze`, `decompile`) are the producer side (scylla-ingest + the engine port) and land
//! on this same session as it grows.

use std::collections::BTreeSet;

use scylla_model::{FactKind, Function, Program, StableId, UserFact};

/// Typed port errors (DD-021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    NoSuchFunction(StableId),
    Decode(String),
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortError::NoSuchFunction(id) => write!(f, "no such function: {id:?}"),
            PortError::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for PortError {}

/// Semantic-zoom altitude (DD-020).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zoom {
    /// Coarsest: just identity + a one-line summary.
    Intent,
    /// Default resting altitude: the domain vocabulary.
    Domain,
    /// Fine escape hatch: everything the v0 model holds.
    Detail,
}

/// A function projected at a [`Zoom`] altitude. Fields above the current altitude are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionView {
    pub id: StableId,
    /// Display name — a user rename wins over the engine symbol (DD-005).
    pub name: String,
    /// One-line summary, present at every altitude.
    pub summary: String,
    pub addr: Option<u64>,
    pub bb_count: Option<u32>,
    pub callees: Option<Vec<String>>,
    pub callers: Option<Vec<String>>,
    pub size: Option<u64>,
}

/// A live analysis session: the client port over one loaded model.
pub struct Session {
    program: Program,
}

impl Session {
    pub fn open(program: Program) -> Self {
        Session { program }
    }

    /// Load a session from a canonical model artifact (DD-026).
    pub fn from_artifact(bytes: &[u8]) -> Result<Self, PortError> {
        // Go through the total validating loader (DD-036), not raw decode.
        scylla_schema::load(bytes)
            .map(|(program, _report)| Session::open(program))
            .map_err(|e| PortError::Decode(e.to_string()))
    }

    /// Serialize the session's model to the canonical artifact.
    pub fn to_artifact(&self) -> Vec<u8> {
        scylla_schema::to_bytes(&self.program)
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    fn func(&self, id: StableId) -> Result<&Function, PortError> {
        self.program
            .functions
            .iter()
            .find(|f| f.id == id)
            .ok_or(PortError::NoSuchFunction(id))
    }

    fn name_of(&self, id: StableId) -> String {
        self.program.display_name(id).unwrap_or_default()
    }

    /// Stable ids of functions that call `id` (call-graph navigation).
    pub fn callers(&self, id: StableId) -> Vec<StableId> {
        self.program
            .functions
            .iter()
            .filter(|f| f.callees.contains(&id))
            .map(|f| f.id)
            .collect()
    }

    /// Project one function at a zoom altitude (DD-020).
    pub fn view(&self, id: StableId, zoom: Zoom) -> Result<FunctionView, PortError> {
        let f = self.func(id)?;
        let name = self.name_of(id);
        let callers = self.callers(id);
        let summary = format!(
            "{name} — {} block(s), {} out-call(s), {} caller(s)",
            f.bb_count,
            f.callees.len(),
            callers.len(),
        );
        let mut v = FunctionView {
            id,
            name,
            summary,
            addr: None,
            bb_count: None,
            callees: None,
            callers: None,
            size: None,
        };
        if zoom != Zoom::Intent {
            v.addr = Some(f.addr);
            v.bb_count = Some(f.bb_count);
            v.callees = Some(f.callees.iter().map(|c| self.name_of(*c)).collect());
            v.callers = Some(callers.iter().map(|c| self.name_of(*c)).collect());
        }
        if zoom == Zoom::Detail {
            v.size = Some(f.size);
        }
        Ok(v)
    }

    /// List all functions at a zoom altitude.
    pub fn functions(&self, zoom: Zoom) -> Vec<FunctionView> {
        let ids: Vec<StableId> = self.program.functions.iter().map(|f| f.id).collect();
        ids.into_iter().map(|id| self.view(id, zoom).unwrap()).collect()
    }

    pub fn rename(&mut self, id: StableId, name: impl Into<String>) -> Result<(), PortError> {
        self.set_fact(id, FactKind::Rename(name.into()))
    }

    pub fn retype(&mut self, id: StableId, ty: impl Into<String>) -> Result<(), PortError> {
        self.set_fact(id, FactKind::Retype(ty.into()))
    }

    pub fn comment(&mut self, id: StableId, text: impl Into<String>) -> Result<(), PortError> {
        self.set_fact(id, FactKind::Comment(text.into()))
    }

    /// Set a fact, replacing an existing fact of the same kind on the same target.
    fn set_fact(&mut self, id: StableId, kind: FactKind) -> Result<(), PortError> {
        self.func(id)?;
        let d = std::mem::discriminant(&kind);
        self.program
            .facts
            .retain(|f| !(f.target == id && std::mem::discriminant(&f.kind) == d));
        self.program.facts.push(UserFact { target: id, kind });
        Ok(())
    }

    /// Coarse-grained diff against another session: ids present only here / only there, by
    /// structural identity. (A first taste of DD-017's `diff` verb.)
    pub fn diff_function_addrs(&self, other: &Session) -> (BTreeSet<u64>, BTreeSet<u64>) {
        let mine: BTreeSet<u64> = self.program.functions.iter().map(|f| f.addr).collect();
        let theirs: BTreeSet<u64> = other.program.functions.iter().map(|f| f.addr).collect();
        (
            mine.difference(&theirs).copied().collect(),
            theirs.difference(&mine).copied().collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATHLIB: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

    fn session() -> Session {
        Session::open(scylla_ingest::snapshot_to_program(MATHLIB).unwrap())
    }

    fn id_of(s: &Session, name: &str) -> StableId {
        s.program().functions.iter().find(|f| f.name == name).unwrap().id
    }

    #[test]
    fn navigates_the_call_graph_by_name() {
        let s = session();
        let main = id_of(&s, "main");
        let view = s.view(main, Zoom::Domain).unwrap();
        assert!(view.callees.unwrap().contains(&"gcd".to_string()));
    }

    #[test]
    fn zoom_controls_detail() {
        let s = session();
        let gcd = id_of(&s, "gcd");
        let intent = s.view(gcd, Zoom::Intent).unwrap();
        assert!(intent.addr.is_none() && intent.size.is_none());
        assert!(!intent.summary.is_empty());
        let detail = s.view(gcd, Zoom::Detail).unwrap();
        assert!(detail.addr.is_some() && detail.size.is_some());
    }

    #[test]
    fn rename_wins_and_propagates_to_callers() {
        let mut s = session();
        let gcd = id_of(&s, "gcd");
        let main = id_of(&s, "main");
        s.rename(gcd, "euclid_gcd").unwrap();
        assert_eq!(s.view(gcd, Zoom::Domain).unwrap().name, "euclid_gcd");
        // the rename shows through in main's callee list, not just on gcd itself
        assert!(s
            .view(main, Zoom::Domain)
            .unwrap()
            .callees
            .unwrap()
            .contains(&"euclid_gcd".to_string()));
    }

    #[test]
    fn annotations_survive_an_artifact_round_trip() {
        let mut s = session();
        let gcd = id_of(&s, "gcd");
        s.rename(gcd, "euclid_gcd").unwrap();
        s.comment(gcd, "Euclid's algorithm").unwrap();
        let bytes = s.to_artifact();
        let reloaded = Session::from_artifact(&bytes).unwrap();
        assert_eq!(reloaded.view(gcd, Zoom::Domain).unwrap().name, "euclid_gcd");
    }

    #[test]
    fn unknown_function_is_a_typed_error() {
        let s = session();
        assert_eq!(s.view(StableId(99999), Zoom::Domain), Err(PortError::NoSuchFunction(StableId(99999))));
    }
}
