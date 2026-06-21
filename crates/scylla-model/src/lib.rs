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
    /// A structural fingerprint of the instruction mix — see [`mnemonic_fingerprint`]. `0` means
    /// the engine emitted no mnemonic data. Used to disambiguate coarse-signature collisions in
    /// re-anchoring (DD-038); it only ever *adds* discrimination, never causes a wrong match.
    pub fingerprint: u64,
}

/// A stable structural fingerprint of a function: the FNV-1a hash of its **mnemonic histogram**
/// (the instruction multiset, sorted — so it is order-independent and deterministic). This is the
/// model-side echo of the prototype's strongest re-anchoring signal (the mnemonic cosine).
///
/// `0` is reserved to mean "no mnemonic data" (e.g. an engine that didn't emit it); a non-empty
/// input never returns `0`. Two functions with the same instruction mix share a fingerprint —
/// which, in the merge signature, makes them *ambiguous* (flagged), never a silent wrong match.
pub fn mnemonic_fingerprint<S: AsRef<str>>(mnemonics: &[S]) -> u64 {
    if mnemonics.is_empty() {
        return 0;
    }
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for m in mnemonics {
        *counts.entry(m.as_ref()).or_default() += 1;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for (mnem, count) in &counts {
        for b in mnem.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h ^= u64::from(*count);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h == 0 {
        1
    } else {
        h
    }
}

/// The kinds of fact an analyst attaches to an entity (DD-001 first-class user facts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactKind {
    Rename(String),
    Retype(String),
    Comment(String),
}

/// Who authored a fact — the **identity seam** (DD-035). `None` in single-user / local v1; a
/// future networked head stamps a real principal without reshaping the core. Provenance
/// (DD-007) and collaboration (DD-027) are the consumers of "who".
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Principal(pub String);

/// A durable user fact: an *edge* onto a stable id (DD-005). Survives re-analysis because
/// it references the stable id, not an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserFact {
    pub target: StableId,
    pub kind: FactKind,
    pub author: Option<Principal>,
}

impl UserFact {
    /// A fact with no recorded author (single-user / local).
    pub fn new(target: StableId, kind: FactKind) -> Self {
        UserFact { target, kind, author: None }
    }

    /// Stamp the authoring principal (the seam).
    pub fn by(mut self, author: Principal) -> Self {
        self.author = Some(author);
        self
    }

    /// Clone this fact onto a new target, preserving kind + author (used by re-anchoring).
    pub fn retarget(&self, target: StableId) -> Self {
        UserFact { target, kind: self.kind.clone(), author: self.author.clone() }
    }
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
                fingerprint: 0,
            }],
            facts: vec![UserFact::new(gcd, FactKind::Rename("gcd".into()))],
        };
        assert_eq!(prog.display_name(gcd).as_deref(), Some("gcd"));
    }

    #[test]
    fn fingerprint_is_order_independent_and_reserves_zero() {
        assert_eq!(mnemonic_fingerprint::<&str>(&[]), 0, "no data -> 0 sentinel");
        let a = mnemonic_fingerprint(&["MOV", "PUSH", "MOV", "RET"]);
        let b = mnemonic_fingerprint(&["MOV", "MOV", "RET", "PUSH"]); // same multiset, reordered
        assert_eq!(a, b, "the histogram is order-independent");
        assert_ne!(a, 0, "non-empty input never collides with the no-data sentinel");
        // A different instruction mix is a different fingerprint.
        assert_ne!(a, mnemonic_fingerprint(&["MOV", "PUSH", "RET"]));
    }
}
