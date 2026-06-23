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

use scylla_model::{FactKind, Function, Principal, Program, StableId, UserFact};

/// Typed port errors (DD-021): a SMALL taxonomy that faithfully mirrors Ghidra's own
/// exception classes, so a head can translate a failure without inventing semantics
/// (pass-through, not a clever new taxonomy). Engine-side failures (decompile timeout,
/// cancellation) map into this set as the port grows to surface those verbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// The target id isn't in the model — navigation/annotation of a missing function.
    NoSuchFunction(StableId),
    /// The model artifact failed to load/decode (the DD-036 validating loader).
    Decode(String),
    /// An annotation value was rejected (e.g. an empty name). Mirrors Ghidra's
    /// `InvalidInputException` / `DuplicateNameException`.
    InvalidInput(String),
}

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortError::NoSuchFunction(id) => write!(f, "no such function: {id:?}"),
            PortError::Decode(e) => write!(f, "decode error: {e}"),
            PortError::InvalidInput(e) => write!(f, "invalid input: {e}"),
        }
    }
}

impl std::error::Error for PortError {}

/// Reject a blank annotation value — the producer of [`PortError::InvalidInput`] (DD-021,
/// mirroring Ghidra's `InvalidInputException`).
fn non_blank(value: &str, msg: &str) -> Result<(), PortError> {
    if value.trim().is_empty() {
        return Err(PortError::InvalidInput(msg.to_string()));
    }
    Ok(())
}

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

/// A semantic diff between two sessions (DD-017 `diff`): functions matched across them by stable
/// structural identity (address-independent), and those on only one side — reported by display
/// name. The address-keyed [`Session::diff_function_addrs`] is the coarse first taste; this is the
/// identity-based verb, built on the merge engine's structural matcher.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionDiff {
    /// `(this_name, other_name)` for each structurally-matched function pair (body unchanged).
    pub matched: Vec<(String, String)>,
    /// `(this_name, other_name)` for each function whose BODY changed but which call-graph
    /// propagation re-identified as the same function (DD-017 "modified" — added vs removed).
    pub changed: Vec<(String, String)>,
    /// Display names of functions present only in this session.
    pub only_here: Vec<String>,
    /// Display names of functions present only in the other session.
    pub only_there: Vec<String>,
}

/// A live analysis session: the client port over one loaded model.
pub struct Session {
    program: Program,
    principal: Option<Principal>,
}

impl Session {
    /// Open a session as the local user (v1 default principal — DD-035).
    pub fn open(program: Program) -> Self {
        Session {
            program,
            principal: Some(Principal("local".into())),
        }
    }

    /// Open as a specific principal — the seam a future networked head uses (DD-035).
    pub fn open_as(program: Program, principal: Principal) -> Self {
        Session {
            program,
            principal: Some(principal),
        }
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
        ids.into_iter()
            .map(|id| self.view(id, zoom).unwrap())
            .collect()
    }

    pub fn rename(&mut self, id: StableId, name: impl Into<String>) -> Result<(), PortError> {
        let name = name.into();
        non_blank(&name, "a function name cannot be empty")?;
        self.set_fact(id, FactKind::Rename(name))
    }

    pub fn retype(&mut self, id: StableId, ty: impl Into<String>) -> Result<(), PortError> {
        let ty = ty.into();
        non_blank(&ty, "a type cannot be empty")?;
        self.set_fact(id, FactKind::Retype(ty))
    }

    /// A comment may be empty — clearing it is a legitimate edit, unlike a name or type.
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
        self.program.facts.push(UserFact {
            target: id,
            kind,
            author: self.principal.clone(),
        });
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

    /// Semantic diff against another session (DD-017 `diff`): pair functions by structural identity
    /// (address-independent — survives recompiles / re-analysis), reporting matched pairs and the
    /// functions unique to each side, by display name. Built on the merge engine's structural
    /// matcher, so a user rename shows through. The proper `diff` verb; supersedes the address-keyed
    /// [`Session::diff_function_addrs`] first taste.
    pub fn diff(&self, other: &Session) -> SessionDiff {
        let d = scylla_merge::diff_programs(&self.program, &other.program);
        SessionDiff {
            matched: d
                .matched
                .into_iter()
                .map(|(a, b)| (self.name_of(a), other.name_of(b)))
                .collect(),
            changed: d
                .changed
                .into_iter()
                .map(|(a, b)| (self.name_of(a), other.name_of(b)))
                .collect(),
            only_here: d.only_a.into_iter().map(|id| self.name_of(id)).collect(),
            only_there: d.only_b.into_iter().map(|id| other.name_of(id)).collect(),
        }
    }

    /// Re-anchor this session's user facts onto `other` — a RE-ANALYSIS of the same program (fresh
    /// stable ids, possibly an address shift) — by structural identity (DD-005), then adopt the
    /// merged model as this session. The mutating sibling of [`Session::diff`]: where `diff` reports
    /// the correspondence, `merge_from` carries the annotations across it. Returns the merge engine's
    /// report (`merged` facts confidently carried, `flagged` left for review — fail-closed: a
    /// near-tie never anchors). `other` is consumed structurally (cloned), not mutated.
    pub fn merge_from(&mut self, other: &Session) -> scylla_merge::MergeReport {
        let mut new = other.program.clone();
        let report = scylla_merge::merge_into(&self.program, &mut new);
        self.program = new;
        report
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
        s.program()
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .id
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
        assert_eq!(
            s.view(StableId(99999), Zoom::Domain),
            Err(PortError::NoSuchFunction(StableId(99999)))
        );
    }

    #[test]
    fn annotations_carry_the_session_principal_and_survive_round_trip() {
        // DD-035 identity seam: an annotation is stamped with the session's principal, and
        // the author persists through the artifact (so collaboration/provenance can use it).
        let mut s = session(); // open() => principal "local"
        let gcd = id_of(&s, "gcd");
        s.rename(gcd, "euclid_gcd").unwrap();
        let f = s.program().facts.iter().find(|f| f.target == gcd).unwrap();
        assert_eq!(f.author, Some(Principal("local".into())));

        let reloaded = Session::from_artifact(&s.to_artifact()).unwrap();
        let rf = reloaded
            .program()
            .facts
            .iter()
            .find(|f| f.target == gcd)
            .unwrap();
        assert_eq!(rf.author, Some(Principal("local".into())));
    }

    #[test]
    fn semantic_diff_pairs_functions_by_identity_not_address() {
        let a = session();
        let b = session(); // same binary, FRESH stable ids -> only structural identity can pair them
        let diff = a.diff(&b);
        // No-wrong: every matched pair is the same function by name.
        for (x, y) in &diff.matched {
            assert_eq!(x, y, "a matched pair must be the same function");
        }
        // The user functions re-pair across the fresh ids (address-independent).
        let names: Vec<&String> = diff.matched.iter().map(|(x, _)| x).collect();
        for n in ["gcd", "fib", "main"] {
            assert!(
                names.contains(&&n.to_string()),
                "{n} should pair with itself"
            );
        }
    }

    #[test]
    fn semantic_diff_reports_a_modified_function_by_name() {
        // DD-017 "modified": gcd's body is edited (its structural signature shifts) but its call
        // edges are intact, so call-graph propagation re-identifies it — `changed`, not removed+added.
        let a = session();
        let mut b_prog = scylla_ingest::snapshot_to_program(MATHLIB).unwrap();
        {
            let g = b_prog
                .functions
                .iter_mut()
                .find(|f| f.name == "gcd")
                .unwrap();
            g.bb_count += 3;
            g.size += 64;
            g.fingerprint ^= 0xA5A5;
        }
        let diff = a.diff(&Session::open(b_prog));
        assert!(
            diff.changed.iter().any(|(x, y)| x == "gcd" && y == "gcd"),
            "gcd reported as changed by name (no-wrong)"
        );
        assert!(
            !diff.only_here.iter().any(|n| n == "gcd"),
            "not double-counted as removed"
        );
        assert!(
            !diff.only_there.iter().any(|n| n == "gcd"),
            "not double-counted as added"
        );
    }

    #[test]
    fn merge_from_reanchors_annotations_onto_a_reanalysis() {
        // DD-005: rename a function, then merge a RE-ANALYSIS (same program, fresh stable ids) — the
        // rename re-anchors onto it by structural identity, and the session becomes the merged model.
        let mut a = session();
        let gcd = id_of(&a, "gcd");
        a.rename(gcd, "euclid_gcd").unwrap();
        let report = a.merge_from(&session()); // a fresh materialization = the re-analysis
        assert!(report.merged >= 1, "the rename should carry: {report:?}");
        assert!(
            a.functions(Zoom::Domain)
                .iter()
                .any(|f| f.name == "euclid_gcd"),
            "euclid_gcd re-anchored onto the fresh-id rebuild"
        );
    }

    #[test]
    fn blank_annotations_are_rejected_as_invalid_input() {
        // DD-021: a name/type must be non-blank (Ghidra's InvalidInputException);
        // a comment may be empty (clearing it is a legitimate edit).
        let mut s = session();
        let gcd = id_of(&s, "gcd");
        assert_eq!(
            s.rename(gcd, ""),
            Err(PortError::InvalidInput(
                "a function name cannot be empty".into()
            ))
        );
        assert!(matches!(
            s.rename(gcd, "   "),
            Err(PortError::InvalidInput(_))
        ));
        assert!(matches!(s.retype(gcd, ""), Err(PortError::InvalidInput(_))));
        assert!(s.rename(gcd, "euclid_gcd").is_ok());
        assert!(s.comment(gcd, "").is_ok());
    }
}
