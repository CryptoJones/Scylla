//! Scylla domain model — the durable, engine-independent RE narrow waist.
//!
//! Decisions realized here:
//! - **DD-001** the model is the domain vocabulary (functions, calls, user facts).
//! - **DD-004** identity is a *synthetic stable id*, minted at first sight; an entity's
//!   address is a mutable **attribute**, never its identity — so facts survive when code moves.
//! - **DD-005** user facts are first-class and durable, attached as edges onto stable ids.
//!
//! v0 scaffold (Sprint 3): minimal but real. Rich types / blocks / xrefs (DD-001 full set)
//! and the identity-anchored merge engine (DD-005) land in later sprints.

/// A runtime address — a mutable *attribute* of an entity, not its identity (DD-004).
pub type Addr = u64;

/// Synthetic stable identity (DD-004). Minted once, never derived from an address, so a
/// user's facts keep pointing at the right entity after re-analysis shifts the code.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct StableId(pub u64);

/// Mints monotonically increasing stable ids ("at first sight").
#[derive(Debug, Default)]
pub struct IdMinter {
    next: u64,
}

impl IdMinter {
    pub fn new() -> Self {
        IdMinter { next: 1 }
    }

    pub fn mint(&mut self) -> StableId {
        let id = StableId(self.next);
        self.next += 1;
        id
    }
}

/// A function — a machine fact. The `name` here is the *engine's* symbol; an analyst's
/// rename lives separately as a [`UserFact`] so re-analysis can't clobber it (DD-005).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub id: StableId,
    pub addr: Addr,
    pub name: String,
    pub size: u64,
    pub bb_count: u32,
    pub callees: Vec<StableId>,
}

/// The kinds of fact an analyst attaches to an entity (DD-001 first-class user facts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactKind {
    Rename(String),
    Retype(String),
    Comment(String),
}

/// A durable user fact: an *edge* onto a stable id (DD-005). Survives re-analysis because
/// it references the stable id, not an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserFact {
    pub target: StableId,
    pub kind: FactKind,
}

/// The analyzed program — the materialized model artifact (DD-026: our own canonical form).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Program {
    pub name: String,
    pub language: String,
    pub functions: Vec<Function>,
    pub facts: Vec<UserFact>,
}

impl Program {
    /// The effective display name of a function: a user rename (DD-005) wins over the
    /// engine's symbol — a tiny first taste of the identity-anchored merge.
    pub fn display_name(&self, id: StableId) -> Option<String> {
        let renamed = self.facts.iter().find_map(|f| match (&f.kind, f.target == id) {
            (FactKind::Rename(n), true) => Some(n.clone()),
            _ => None,
        });
        renamed.or_else(|| {
            self.functions
                .iter()
                .find(|f| f.id == id)
                .map(|f| f.name.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minter_is_monotonic_and_address_independent() {
        let mut m = IdMinter::new();
        let a = m.mint();
        let b = m.mint();
        assert_ne!(a, b);
        assert_eq!(a, StableId(1));
        assert_eq!(b, StableId(2));
    }

    #[test]
    fn user_rename_wins_over_engine_symbol() {
        let mut m = IdMinter::new();
        let gcd = m.mint();
        let prog = Program {
            name: "mathlib".into(),
            language: "x86:LE:64:default".into(),
            functions: vec![Function {
                id: gcd,
                addr: 0x401156,
                name: "FUN_00401156".into(),
                size: 64,
                bb_count: 4,
                callees: vec![],
            }],
            facts: vec![UserFact {
                target: gcd,
                kind: FactKind::Rename("gcd".into()),
            }],
        };
        assert_eq!(prog.display_name(gcd).as_deref(), Some("gcd"));
    }
}
