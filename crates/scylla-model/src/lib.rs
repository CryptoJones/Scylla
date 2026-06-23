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
    /// A structural fingerprint of the instruction mix — the FNV-1a hash of [`Function::mnemonics`]
    /// (see [`mnemonic_fingerprint`]). `0` = the engine emitted no mnemonic data. Used to
    /// disambiguate coarse-signature collisions in EXACT re-anchoring (DD-038); it only ever *adds*
    /// discrimination, never a wrong match.
    pub fingerprint: u64,
    /// The function's **mnemonic histogram** — the instruction multiset, sorted by mnemonic (so it
    /// is order-independent and deterministic). Empty = no data. The FUZZY re-anchoring matcher
    /// scores cosine similarity over these to recover cross-build matches the exact fingerprint
    /// can't; the `fingerprint` above is just its hash, cached for the fast exact path.
    pub mnemonics: Vec<(String, u32)>,
    /// The function's **ordered mnemonic trigrams** (see [`mnemonic_trigrams`]) — the instruction
    /// stream's length-3 windows, as a sorted histogram. Where [`Function::mnemonics`] is the
    /// order-INDEPENDENT multiset, these encode local instruction order, so the fuzzy matcher can
    /// tell apart two functions with the same instruction mix but different flow. Empty when the
    /// function has < 3 instructions or the producer emitted no mnemonics. Computed at producer time
    /// (the ordered stream isn't otherwise persisted) and stored in the artifact.
    pub trigrams: Vec<(String, u32)>,
    /// **Arch-independent** features (DD-041): the string literals this function references and the
    /// imported/library symbols it calls *by name*. Unlike mnemonics and addresses, these survive
    /// recompilation for a *different ISA* — x86-64 and aarch64 share neither instruction set nor
    /// layout, but the same source references the same `"Error: %s"` and calls the same `printf`.
    /// They drive the cross-architecture ANCHOR re-anchoring pass, where mnemonic cosine is ~0.
    /// Sorted + deduped (set semantics) so they are deterministic and Jaccard-comparable.
    pub string_refs: Vec<String>,
    /// Imported/library call targets by name (`printf`, `atoi`, …) — see [`Function::string_refs`].
    pub imports: Vec<String>,
    /// **Package-qualified** names of called functions (`fmt.Fprintf`, `main.fib`, `runtime.convT64`)
    /// — the Go cross-architecture lever (DD-043). Go keeps fully-qualified names in `.gopclntab`
    /// even when the binary is stripped, and the set is identical across ISAs, so it anchors Go where
    /// strings/imports can't. Deliberately only the *dotted* names: C's bare local names (which do
    /// NOT survive stripping) are excluded, so they never inflate recovery beyond stripped reality.
    pub callee_names: Vec<String>,
    /// **BSim** decompiler-signature feature vector (DD-044): the function's LSH p-code feature
    /// vector as sparse `(feature_hash, weight_bits)` pairs, where `weight_bits` is the IEEE-754
    /// bit pattern of the f32 coefficient (`f32::to_bits`) so the model stays `Eq`/`Hash`-derivable
    /// and round-trips bit-exactly. Empty when the producer emitted no BSim signal (older snapshots,
    /// the gRPC path before the DD-044 producer). It is the ISA-abstracting cross-architecture lever
    /// for the symmetric arithmetic leaves that strings/imports/callee-names/mnemonics/graph-position
    /// all miss — a *weighted cosine* over these vectors reproduces Ghidra's `LSHVector.compare`
    /// exactly, because the producer bakes the feature weights into the coefficients.
    pub bsim_vector: Vec<(u32, u32)>,
}

/// The mnemonic histogram of a function: the instruction multiset, sorted by mnemonic (so it is
/// order-independent and deterministic). The fuzzy re-anchoring matcher scores cosine over these.
pub fn mnemonic_histogram<S: AsRef<str>>(mnemonics: &[S]) -> Vec<(String, u32)> {
    let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for m in mnemonics {
        *counts.entry(m.as_ref()).or_default() += 1;
    }
    counts.into_iter().map(|(m, c)| (m.to_string(), c)).collect()
}

/// The function's **ordered mnemonic trigrams** as a histogram: every length-3 window of the
/// instruction stream (`"mov add cmp"`), counted and sorted. Unlike the order-INDEPENDENT
/// [`mnemonic_histogram`], a trigram encodes *local instruction order*, so two functions with the
/// same instruction multiset but different control/data flow no longer score identical — the order
/// signal the plain histogram throws away. Fewer than 3 mnemonics → empty (no window). Sorted for
/// determinism, like the histogram, and comparable with the same cosine the fuzzy matcher uses.
pub fn mnemonic_trigrams<S: AsRef<str>>(mnemonics: &[S]) -> Vec<(String, u32)> {
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for w in mnemonics.windows(3) {
        let key = format!("{} {} {}", w[0].as_ref(), w[1].as_ref(), w[2].as_ref());
        *counts.entry(key).or_default() += 1;
    }
    counts.into_iter().collect()
}

/// FNV-1a hash of a (sorted) mnemonic histogram. `0` is reserved to mean "no mnemonic data"; a
/// non-empty histogram never returns `0`. Two functions with the same instruction mix share a
/// fingerprint — which, in the merge signature, makes them *ambiguous* (flagged), never wrong.
pub fn histogram_fingerprint(histogram: &[(String, u32)]) -> u64 {
    if histogram.is_empty() {
        return 0;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for (mnem, count) in histogram {
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

/// FNV-1a fingerprint of a function's mnemonics (convenience over the raw, in-order list). Equal
/// to `histogram_fingerprint(&mnemonic_histogram(mnemonics))`. `0` = no data.
pub fn mnemonic_fingerprint<S: AsRef<str>>(mnemonics: &[S]) -> u64 {
    histogram_fingerprint(&mnemonic_histogram(mnemonics))
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
                mnemonics: vec![],
                trigrams: vec![],
                string_refs: vec![],
                imports: vec![],
                callee_names: vec![],
                bsim_vector: vec![],
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
        // The histogram is the sorted multiset; the fingerprint is its hash.
        let h = mnemonic_histogram(&["MOV", "PUSH", "MOV", "RET"]);
        assert_eq!(h, vec![("MOV".into(), 2), ("PUSH".into(), 1), ("RET".into(), 1)]);
        assert_eq!(histogram_fingerprint(&h), a);
    }

    #[test]
    fn trigrams_capture_the_order_the_histogram_loses() {
        // Fewer than 3 mnemonics -> no window, no trigrams.
        assert!(mnemonic_trigrams::<&str>(&[]).is_empty());
        assert!(mnemonic_trigrams(&["MOV", "RET"]).is_empty());

        // Sliding length-3 windows, counted and sorted (deterministic).
        let t = mnemonic_trigrams(&["MOV", "ADD", "CMP", "MOV", "ADD", "CMP"]);
        assert_eq!(
            t,
            vec![
                ("ADD CMP MOV".into(), 1),
                ("CMP MOV ADD".into(), 1),
                ("MOV ADD CMP".into(), 2),
            ]
        );

        // The whole point: two streams with the SAME instruction multiset (identical histogram) but
        // different ORDER yield DIFFERENT trigrams — the signal the order-independent histogram drops.
        assert_eq!(
            mnemonic_histogram(&["MOV", "ADD", "RET"]),
            mnemonic_histogram(&["ADD", "MOV", "RET"]),
            "same multiset -> identical histogram"
        );
        assert_ne!(
            mnemonic_trigrams(&["MOV", "ADD", "RET"]),
            mnemonic_trigrams(&["ADD", "MOV", "RET"]),
            "but the trigrams differ -> order is captured"
        );
    }
}
