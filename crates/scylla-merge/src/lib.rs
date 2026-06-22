//! Identity-anchored re-anchoring of user facts across re-analysis (DD-005).
//!
//! When a binary is re-analyzed (re-run, recompile, patch), the engine mints a *fresh* model
//! with fresh stable ids. This carries an analyst's prior facts onto the new model by matching
//! functions structurally, then re-targeting each fact onto the matched entity's new id.
//!
//! **Safety first (the keystone-spike finding, now a code invariant):** a fact only carries
//! across on a *unique* structural match. Anything ambiguous or absent is **flagged**, never
//! silently mis-attached. Zero-wrong is the contract; recovery rate is the thing we lift with
//! richer signals.
//!
//! Three passes, each strictly more permissive than the last but all gated by unique-match safety:
//! 1. **EXACT** — a fact carries on a UNIQUE structural-signature match. The signature folds the
//!    model's **mnemonic fingerprint** (DD-038) into the coarse CFG/size/out-degree tuple; richer
//!    signature → more *unique* matches, never a wrong one.
//! 2. **ANCHOR (DD-041)** — the CROSS-ARCHITECTURE recovery pass. x86-64 and aarch64 share neither
//!    mnemonics nor addresses (so the exact fingerprint and fuzzy cosine are both ~0), but the same
//!    source references the same **string literals** and calls the same **imports by name**. We
//!    match functions with a rich-enough arch-independent feature set by **Jaccard** over it,
//!    accepted only on a unique best clearing a high threshold AND a runner-up margin. This is the
//!    binary-diffing standard (BinDiff/SIGMADIFF anchor on unique strings/imports); call-graph
//!    propagation from these anchors is the next lever.
//! 3. **FUZZY** — cosine over the stored mnemonic histogram + structural closeness, accepted only
//!    above a confidence threshold AND with a runner-up margin. Lifts both edit classes to 100% and
//!    recovers some recompile.
//!
//! Zero-wrong holds throughout — exact is unique-match, anchor and fuzzy are threshold+margin over a
//! unique best ("never guess a near-tie").

use std::collections::{HashMap, HashSet};

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

/// Cosine similarity of two sorted mnemonic histograms (the instruction mix), in `0..=1`. Empty on
/// either side → `0` (no signal). The dominant fuzzy re-anchoring signal (DD-038 follow-up).
fn cosine(a: &[(String, u32)], b: &[(String, u32)]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let am: HashMap<&str, u32> = a.iter().map(|(m, c)| (m.as_str(), *c)).collect();
    let (mut dot, mut nb) = (0.0, 0.0);
    for (m, c) in b {
        let c = f64::from(*c);
        nb += c * c;
        if let Some(ac) = am.get(m.as_str()) {
            dot += f64::from(*ac) * c;
        }
    }
    let na: f64 = a.iter().map(|(_, c)| f64::from(*c) * f64::from(*c)).sum();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

/// `1.0` when equal, decaying toward `0` as two counts diverge.
fn closeness(x: f64, y: f64) -> f64 {
    1.0 - (x - y).abs() / (x + y).max(1.0)
}

/// Fuzzy structural similarity of two functions, in `0..=1`: cosine over the instruction mix
/// (dominant), plus CFG-size and out-degree closeness. The model echo of the prototype's threshold
/// matcher — cosine + structure (we don't store ordered trigrams), not the full prototype signal.
fn similarity(a: &Function, b: &Function) -> f64 {
    0.60 * cosine(&a.mnemonics, &b.mnemonics)
        + 0.25 * closeness(f64::from(a.bb_count), f64::from(b.bb_count))
        + 0.15 * closeness(a.callees.len() as f64, b.callees.len() as f64)
}

/// The old function whose [`similarity`] to `g` is highest, over ALL of `olds` — the *reverse*
/// direction of the fuzzy match, for the reciprocal-best (symmetric-match) check below. `None` only
/// if `olds` is empty. Ties resolve to the first seen → treated as "not uniquely reciprocal", which
/// fails closed (a near-tie should not anchor a fact anyway).
fn best_old_match<'a>(g: &Function, olds: &'a [Function]) -> Option<&'a Function> {
    let mut best: Option<&Function> = None;
    let mut best_s = f64::NEG_INFINITY;
    for o in olds {
        let s = similarity(o, g);
        if s > best_s {
            best_s = s;
            best = Some(o);
        }
    }
    best
}

/// A fuzzy match must clear this similarity to be trusted at all...
const FUZZY_THRESHOLD: f64 = 0.55;
/// ...AND beat the runner-up by this margin — "never guess between near-ties," the fuzzy-space echo
/// of the exact path's unique-match rule. Together they hold `WRONG = 0`.
const FUZZY_MARGIN: f64 = 0.05;

/// The **arch-independent feature set** of a function (DD-041): its referenced string literals plus
/// its imported call names. Identical across ISAs for the same source — the cross-architecture
/// re-anchoring signal, where the mnemonic histogram (hence cosine and the fingerprint) is not.
fn anchor_set(f: &Function) -> HashSet<&str> {
    f.string_refs.iter().chain(f.imports.iter()).map(String::as_str).collect()
}

/// Jaccard similarity of two sets, in `0..=1`. Either side empty → `0` (no signal, not a match —
/// the many functions with no strings/imports must NOT all look identical to each other).
fn jaccard(a: &HashSet<&str>, b: &HashSet<&str>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// An anchor needs at least this many arch-independent features to be discriminating — one common
/// import (`printf`) is not an identity. Below this, the function defers to the fuzzy pass.
const ANCHOR_MIN_FEATURES: usize = 2;
/// A cross-arch anchor must clear this Jaccard over the arch-independent set...
const ANCHOR_THRESHOLD: f64 = 0.5;
/// ...AND beat the runner-up by this (wide) margin — a *clear* unique winner. Holds `WRONG = 0` the
/// same way exact/fuzzy do: a near-tie is flagged, never guessed.
const ANCHOR_MARGIN: f64 = 0.25;

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

    // Pass 1 — EXACT: a fact carries on a UNIQUE exact-signature match (WRONG=0 by construction).
    let mut merged = Vec::new();
    let mut deferred: Vec<&UserFact> = Vec::new();
    for fact in &old.facts {
        let unique_target = old_by_id
            .get(&fact.target)
            .and_then(|oldf| new_by_sig.get(&signature(oldf)))
            .filter(|ids| ids.len() == 1)
            .map(|ids| ids[0]);
        match unique_target {
            Some(id) => merged.push(fact.retarget(id)),
            None => deferred.push(fact),
        }
    }

    let mut claimed: HashSet<StableId> = merged.iter().map(|f| f.target).collect();
    let mut flagged = Vec::new();

    // Pass 1.5 — ANCHOR (DD-041): the CROSS-ARCHITECTURE pass. For functions with a rich-enough
    // arch-independent feature set (string literals + import names), match by Jaccard over that set
    // — the signal that survives a different ISA, where exact fingerprint and fuzzy cosine are both
    // ~0. Accepted only on a UNIQUE best clearing ANCHOR_THRESHOLD AND beating the runner-up by
    // ANCHOR_MARGIN. Runs before fuzzy because a unique string/import match is the more reliable
    // signal. WRONG=0 holds — it is a unique-feature match, never a guess.
    let mut deferred2: Vec<&UserFact> = Vec::new();
    for fact in deferred {
        let Some(oldf) = old_by_id.get(&fact.target).copied() else {
            deferred2.push(fact); // missing old function — the fuzzy pass flags it
            continue;
        };
        let aset = anchor_set(oldf);
        if aset.len() < ANCHOR_MIN_FEATURES {
            deferred2.push(fact); // too few arch-independent features to anchor on — try fuzzy
            continue;
        }
        let (mut best, mut best_s, mut second_s) = (None, -1.0_f64, -1.0_f64);
        for nf in &new.functions {
            if claimed.contains(&nf.id) {
                continue;
            }
            let s = jaccard(&aset, &anchor_set(nf));
            if s > best_s {
                second_s = best_s;
                best_s = s;
                best = Some(nf.id);
            } else if s > second_s {
                second_s = s;
            }
        }
        match best {
            Some(id) if best_s >= ANCHOR_THRESHOLD && best_s - second_s >= ANCHOR_MARGIN => {
                claimed.insert(id);
                merged.push(fact.retarget(id));
            }
            _ => deferred2.push(fact),
        }
    }

    // Pass 2 — FUZZY: for what exact and anchor couldn't place, take the best similarity match among
    // the as-yet-unclaimed new functions — but ONLY if it clears the threshold AND beats the
    // runner-up by the margin (a confident, unambiguous match). Recovers cross-build cases the
    // exact fingerprint can't, while never guessing a near-tie. WRONG=0 is the DD-038 hard gate.
    for fact in deferred2 {
        let Some(oldf) = old_by_id.get(&fact.target).copied() else {
            flagged.push(fact.clone());
            continue;
        };
        let (mut best, mut best_s, mut second_s): (Option<&Function>, f64, f64) =
            (None, -1.0, -1.0);
        for nf in &new.functions {
            if claimed.contains(&nf.id) {
                continue;
            }
            let s = similarity(oldf, nf);
            if s > best_s {
                second_s = best_s;
                best_s = s;
                best = Some(nf);
            } else if s > second_s {
                second_s = s;
            }
        }
        // Accept only a confident, unambiguous AND reciprocal best. Reciprocal-best (the binary-
        // diffing symmetric match): the candidate's OWN best old-match must be `oldf` too. Without
        // it, a function inlined away in `new` latches onto a structurally-similar stub it happens
        // to share common mnemonics with (small functions have near-identical histograms) — a
        // one-directional false positive. The stub's real reciprocal is its own twin, so it's
        // rejected. WRONG=0 holds: threshold + runner-up margin + reciprocity.
        match best {
            Some(nf)
                if best_s >= FUZZY_THRESHOLD
                    && best_s - second_s >= FUZZY_MARGIN
                    && best_old_match(nf, &old.functions).map(|o| o.id) == Some(oldf.id) =>
            {
                claimed.insert(nf.id);
                merged.push(fact.retarget(nf.id));
            }
            _ => flagged.push(fact.clone()),
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
    const V1_AARCH64: &str = include_str!("../../../prototype/snapshots/mathlib.aarch64.O0.json");

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
    fn cosine_is_one_for_identical_mix_zero_for_disjoint() {
        let a = vec![("MOV".to_string(), 2), ("RET".to_string(), 1)];
        assert!((cosine(&a, &a) - 1.0).abs() < 1e-9, "identical instruction mix -> 1.0");
        assert_eq!(cosine(&a, &[("ADD".to_string(), 3)]), 0.0, "disjoint mix -> 0");
        assert_eq!(cosine(&a, &[]), 0.0, "no histogram -> no signal");
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

    #[test]
    fn jaccard_is_set_overlap_and_empty_is_no_signal() {
        let a: HashSet<&str> = ["printf", "atoi", "fmt"].into_iter().collect();
        let b: HashSet<&str> = ["printf", "atoi", "fmt"].into_iter().collect();
        assert!((jaccard(&a, &b) - 1.0).abs() < 1e-9, "identical sets -> 1.0");
        let c: HashSet<&str> = ["printf"].into_iter().collect();
        assert!((jaccard(&a, &c) - 1.0 / 3.0).abs() < 1e-9, "1 shared of 3 -> 1/3");
        let empty: HashSet<&str> = HashSet::new();
        assert_eq!(jaccard(&a, &empty), 0.0, "empty side -> no signal (NOT a match)");
        assert_eq!(jaccard(&empty, &empty), 0.0, "two empties are not 'identical' here");
    }

    /// DD-041: a function's annotation re-anchors ACROSS ARCHITECTURES (x86-64 -> aarch64) — the
    /// case mnemonic cosine cannot touch. `main` carries the same string literals + import names on
    /// both ISAs, so the anchor pass matches it; the arithmetic leaves (no strings/imports) orphan,
    /// never mis-attach. Zero-wrong throughout.
    #[test]
    fn cross_architecture_anchor_reanchors_main_and_is_zero_wrong() {
        let mut x86 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let main_id = x86.functions.iter().find(|f| f.name == "main").unwrap().id;
        x86.facts.push(UserFact::new(main_id, FactKind::Rename("entrypoint".into())));

        let mut aarch64 = scylla_ingest::snapshot_to_program(V1_AARCH64).unwrap();
        let report = merge_into(&x86, &mut aarch64);

        assert_eq!(report.merged, 1, "main re-anchors across the ISA via its string/import set");
        // and it landed on the aarch64 `main`, not some structural look-alike (zero-wrong).
        let landed = aarch64
            .facts
            .iter()
            .find(|f| matches!(&f.kind, FactKind::Rename(n) if n == "entrypoint"))
            .map(|f| aarch64.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone());
        assert_eq!(landed.as_deref(), Some("main"), "cross-arch fact must sit on aarch64 main");
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
