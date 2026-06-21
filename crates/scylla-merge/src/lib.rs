//! Identity-anchored re-anchoring of user facts across re-analysis (DD-005).
//!
//! When a binary is re-analyzed (re-run, recompile, patch), the engine mints a *fresh* model
//! with fresh stable ids. This carries an analyst's prior facts onto the new model by matching
//! functions structurally, then re-targeting each fact onto the matched entity's new id.
//!
//! **Safety first (the keystone-spike finding, now a code invariant):** a fact only carries
//! across on a *unique* structural match. Anything ambiguous or absent is **flagged**, never
//! silently mis-attached. Zero-wrong is the contract; recovery rate is the thing we lift with
//! richer signals. The signature now folds in the model's **mnemonic fingerprint** (DD-038) on
//! top of the coarse CFG/size/out-degree tuple — which disambiguates collisions and lifts the
//! re-anchoring floors, while keeping zero-wrong by construction (more signature → more *unique*
//! matches, never a wrong one). Fuzzy/cross-build recovery (cosine similarity, Ghidra Version
//! Tracking) is the next lever, per the prototype REPORT.md.

use std::collections::HashMap;

use scylla_model::{FactKind, Function, Program, StableId, UserFact};

/// Structural signature: CFG size, byte size, out-degree, and the **mnemonic fingerprint**
/// (DD-038). Two functions with the same signature are indistinguishable (→ ambiguous → flagged),
/// never guessed between — so a richer signature only ever *adds* discrimination (more functions
/// become uniquely matchable, so more facts survive) and can never turn an ambiguous case into a
/// wrong one. A `0` fingerprint (engine emitted no mnemonics) contributes nothing, degrading
/// cleanly to the old coarse tuple.
fn signature(f: &Function) -> (u32, u64, usize, u64) {
    (f.bb_count, f.size, f.callees.len(), f.fingerprint)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Facts confidently re-anchored onto the new model.
    pub merged: usize,
    /// Facts that couldn't be re-anchored uniquely — surfaced for analyst review.
    pub flagged: usize,
}

/// Compute the re-anchoring of `old`'s facts against `new`, without mutating either.
/// Returns `(merged_facts, flagged_facts)`.
pub fn reanchor_facts(old: &Program, new: &Program) -> (Vec<UserFact>, Vec<UserFact>) {
    let mut new_by_sig: HashMap<(u32, u64, usize, u64), Vec<StableId>> = HashMap::new();
    for f in &new.functions {
        new_by_sig.entry(signature(f)).or_default().push(f.id);
    }
    let old_by_id: HashMap<StableId, &Function> =
        old.functions.iter().map(|f| (f.id, f)).collect();

    let mut merged = Vec::new();
    let mut flagged = Vec::new();
    for fact in &old.facts {
        let unique_target = old_by_id
            .get(&fact.target)
            .and_then(|oldf| new_by_sig.get(&signature(oldf)))
            .filter(|ids| ids.len() == 1)
            .map(|ids| ids[0]);
        match unique_target {
            Some(id) => merged.push(fact.retarget(id)),
            None => flagged.push(fact.clone()),
        }
    }
    (merged, flagged)
}

/// Carry `old`'s user facts onto `new` in place; returns the merge report.
pub fn merge_into(old: &Program, new: &mut Program) -> MergeReport {
    let (mut merged, flagged) = reanchor_facts(old, new);
    let report = MergeReport { merged: merged.len(), flagged: flagged.len() };
    new.facts.append(&mut merged);
    report
}

/// A disagreement found while merging another analyst's work: both gave the same *kind* of
/// fact to the same entity, with different values. Surfaced, never auto-resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub target: StableId,
    pub ours: FactKind,
    pub theirs: FactKind,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CollabReport {
    /// Incoming facts cleanly added to `base`.
    pub merged: usize,
    /// Same entity + same fact kind, different value — surfaced as a [`Conflict`].
    pub conflicts: usize,
    /// Incoming facts that couldn't be re-anchored onto `base` (flagged, not lost).
    pub flagged: usize,
}

/// Merge another analyst's facts into `base` — **git for reverse engineering** (DD-027).
///
/// `incoming` is a *separate materialization of the same binary* (its own stable ids). Each
/// incoming fact is re-anchored onto `base` structurally; clean ones are added, identical
/// ones are no-ops, and genuine disagreements are returned as [`Conflict`]s — `base` is never
/// silently overwritten.
pub fn collaborate(base: &mut Program, incoming: &Program) -> (CollabReport, Vec<Conflict>) {
    let mut base_by_sig: HashMap<(u32, u64, usize, u64), Vec<StableId>> = HashMap::new();
    for f in &base.functions {
        base_by_sig.entry(signature(f)).or_default().push(f.id);
    }
    let incoming_by_id: HashMap<StableId, &Function> =
        incoming.functions.iter().map(|f| (f.id, f)).collect();

    let mut report = CollabReport::default();
    let mut conflicts = Vec::new();
    let mut to_add = Vec::new();
    for fact in &incoming.facts {
        let base_target = incoming_by_id
            .get(&fact.target)
            .and_then(|inf| base_by_sig.get(&signature(inf)))
            .filter(|ids| ids.len() == 1)
            .map(|ids| ids[0]);
        let Some(tid) = base_target else {
            report.flagged += 1;
            continue;
        };
        let kind_disc = std::mem::discriminant(&fact.kind);
        let existing = base
            .facts
            .iter()
            .find(|bf| bf.target == tid && std::mem::discriminant(&bf.kind) == kind_disc);
        match existing {
            Some(bf) if bf.kind != fact.kind => {
                conflicts.push(Conflict {
                    target: tid,
                    ours: bf.kind.clone(),
                    theirs: fact.kind.clone(),
                });
                report.conflicts += 1;
            }
            Some(_) => {} // identical — the analysts already agree
            None => {
                to_add.push(fact.retarget(tid));
                report.merged += 1;
            }
        }
    }
    base.facts.extend(to_add);
    (report, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::FactKind;

    const V1: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");
    const V2: &str = include_str!("../../../prototype/snapshots/mathlib_v2.x86-64.O0.json");

    fn annotate(p: &mut Program) {
        let gcd = p.functions.iter().find(|f| f.name == "gcd").unwrap().id;
        let fib = p.functions.iter().find(|f| f.name == "fib").unwrap().id;
        p.facts.push(UserFact::new(gcd, FactKind::Rename("euclid_gcd".into())));
        p.facts.push(UserFact::new(fib, FactKind::Comment("recursive".into())));
    }

    /// Every merged fact must sit on the correctly-named function (names = ground truth).
    fn assert_zero_wrong(p: &Program) {
        let name_of = |id: StableId| {
            p.functions.iter().find(|f| f.id == id).map(|f| f.name.clone())
        };
        for fact in &p.facts {
            match &fact.kind {
                FactKind::Rename(n) if n == "euclid_gcd" => {
                    assert_eq!(name_of(fact.target).as_deref(), Some("gcd"))
                }
                FactKind::Comment(c) if c == "recursive" => {
                    assert_eq!(name_of(fact.target).as_deref(), Some("fib"))
                }
                _ => {}
            }
        }
    }

    #[test]
    fn re_analysis_reanchors_and_is_zero_wrong() {
        let mut v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        annotate(&mut v1);
        let mut fresh = scylla_ingest::snapshot_to_program(V1).unwrap(); // fresh ids
        let report = merge_into(&v1, &mut fresh);
        assert!(report.merged >= 1, "unchanged functions must re-anchor on re-analysis");
        assert_zero_wrong(&fresh);
    }

    #[test]
    fn minor_edit_reanchors_and_is_zero_wrong() {
        let mut v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        annotate(&mut v1);
        let mut v2 = scylla_ingest::snapshot_to_program(V2).unwrap(); // lcm inserted
        let report = merge_into(&v1, &mut v2);
        assert!(report.merged >= 1, "gcd/fib (unchanged) should survive the edit");
        assert_zero_wrong(&v2);
    }

    // --- DD-027 collaboration (git-for-RE): merging two analysts' work ---

    #[test]
    fn collaboration_merges_non_conflicting_facts() {
        let mut a = scylla_ingest::snapshot_to_program(V1).unwrap();
        let b_src = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut b = b_src;
        let a_main = a.functions.iter().find(|f| f.name == "main").unwrap().id;
        let b_fib = b.functions.iter().find(|f| f.name == "fib").unwrap().id;
        a.facts.push(UserFact::new(a_main, FactKind::Rename("entrypoint".into())));
        b.facts.push(UserFact::new(b_fib, FactKind::Comment("recursive".into())));
        let (report, conflicts) = collaborate(&mut a, &b);
        assert_eq!(conflicts.len(), 0);
        assert_eq!(report.merged, 1, "fib's comment should merge in");
        assert!(a.facts.iter().any(|f| matches!(&f.kind, FactKind::Comment(c) if c == "recursive")));
    }

    #[test]
    fn collaboration_surfaces_conflicts_without_overwriting() {
        let mut a = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut b = scylla_ingest::snapshot_to_program(V1).unwrap();
        let a_fib = a.functions.iter().find(|f| f.name == "fib").unwrap().id;
        let b_fib = b.functions.iter().find(|f| f.name == "fib").unwrap().id;
        a.facts.push(UserFact::new(a_fib, FactKind::Rename("fib_a".into())));
        b.facts.push(UserFact::new(b_fib, FactKind::Rename("fib_b".into())));
        let (report, conflicts) = collaborate(&mut a, &b);
        assert_eq!(report.conflicts, 1);
        assert_eq!(conflicts.len(), 1);
        // base keeps its own value — incoming never silently overwrites it
        assert!(a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "fib_a")));
        assert!(!a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "fib_b")));
    }
}
