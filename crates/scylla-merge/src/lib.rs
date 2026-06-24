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
//!    binary-diffing standard (BinDiff/SIGMADIFF anchor on unique strings/imports). Call-graph
//!    **propagation** from these anchors is now realized in the `diff` verb ([`diff_programs`]): a
//!    leftover function re-identified by its unique neighbourhood of already-matched callers/callees
//!    is recovered — as `matched` if its body is unchanged (signature-ambiguous twin), or as
//!    `changed` if its body differs (the "modified" class). Iterated to a fixpoint, fail-closed.
//! 3. **FUZZY** — cosine over the stored mnemonic histogram AND its ordered trigrams (the latter
//!    captures the local instruction order the histogram drops) + structural closeness, accepted
//!    only above a confidence threshold AND with a runner-up margin. Lifts both edit classes to
//!    100% and recovers some recompile.
//!
//! Zero-wrong holds throughout — exact is unique-match, anchor and fuzzy are threshold+margin over a
//! unique best ("never guess a near-tie").

use std::collections::{BTreeSet, HashMap, HashSet};

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

/// Fuzzy structural similarity of two functions, in `0..=1`: the instruction-mix signal (dominant),
/// plus CFG-size and out-degree closeness. The instruction-mix signal blends the order-INDEPENDENT
/// mnemonic histogram with the ORDERED-trigram histogram (`mov add cmp` windows) — trigrams pull
/// apart two functions with the same instruction multiset but different flow, the discrimination a
/// bag-of-mnemonics throws away. When either side has no trigrams (a function under 3 instructions,
/// or a pre-trigram artifact), the whole instruction-mix weight falls back to the unigram cosine, so
/// short functions and older artifacts score exactly as before (no regression, no WRONG introduced —
/// the threshold + margin + reciprocal-best gates are unchanged; a sharper signal only separates
/// near-ties further or drops a match below threshold, never invents one).
fn similarity(a: &Function, b: &Function) -> f64 {
    let structure = 0.25 * closeness(f64::from(a.bb_count), f64::from(b.bb_count))
        + 0.15 * closeness(a.callees.len() as f64, b.callees.len() as f64);
    let unigram = cosine(&a.mnemonics, &b.mnemonics);
    let mix = if a.trigrams.is_empty() || b.trigrams.is_empty() {
        0.60 * unigram
    } else {
        0.35 * unigram + 0.25 * cosine(&a.trigrams, &b.trigrams)
    };
    mix + structure
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

/// The **arch-independent feature set** of a function (DD-041, DD-043): its referenced string
/// literals, its imported call names, and its **package-qualified callee names** (`fmt.Fprintf`,
/// `main.fib` — the Go lever; survive pclntab stripping, ISA-stable, empty for stripped C). Identical
/// across ISAs for the same source — the cross-architecture re-anchoring signal, where the mnemonic
/// histogram (hence cosine and the fingerprint) is not.
fn anchor_set(f: &Function) -> HashSet<&str> {
    f.string_refs
        .iter()
        .chain(f.imports.iter())
        .chain(f.callee_names.iter())
        .map(String::as_str)
        .collect()
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

/// Recursion-match weight in the propagation score: a *self-recursive* function matching another
/// self-recursive one is a strong, ISA-independent signal (it survives any recompile) — heavy
/// enough to break a tie among graph-neighbors that are otherwise symmetric (e.g. the 4 leaves all
/// called once by `main`, of which only `fib` calls itself).
const PROP_RECURSION_WEIGHT: f64 = 2.0;
/// A propagated match needs at least this much matched-neighbor agreement — a function with NO
/// confirmed neighbor in common with the candidate is not "propagated", it is guessed.
const PROP_MIN_AGREEMENT: f64 = 1.0;
/// ...AND must beat the runner-up by this margin. Integer agreements + the recursion weight make
/// the real margins 0, 1, 2, …; a genuine distinction (a recursion match, or a higher matched
/// in-degree) clears 1.0, while symmetric neighbors tie at margin 0 and are flagged. `WRONG = 0`.
const PROP_MARGIN: f64 = 1.0;

/// Invert `callees` into a caller adjacency: `id -> [functions that call id]`.
fn caller_map(funcs: &[Function]) -> HashMap<StableId, Vec<StableId>> {
    let mut m: HashMap<StableId, Vec<StableId>> = HashMap::new();
    for f in funcs {
        for c in &f.callees {
            m.entry(*c).or_default().push(f.id);
        }
    }
    m
}

/// PROPAGATION (DD-041 follow-up): match `b_id` (old) by its position in the call graph relative to
/// the functions already matched. Restricts candidates to the graph-LOCAL new functions — callees of
/// the images of `b`'s matched callers, and callers of the images of `b`'s matched callees — and
/// scores each by how much of that confirmed neighborhood it reproduces (plus a self-recursion
/// match). This is the one cross-architecture discriminator that is NOT structural: x86 and aarch64
/// `gcd` are indistinguishable by size/bb (proven — all the leaves share bb_count and size is
/// misleading across the ISA), but `fib` is the unique self-recursive callee of `main`, and a callee
/// called by two matched functions outranks one called by one. Accept only a unique winner clearing
/// `PROP_MIN_AGREEMENT` AND beating the runner-up by `PROP_MARGIN`; symmetric neighbors tie and stay
/// flagged. Builds only on already-confirmed (WRONG=0) matches, so it never cascades a wrong guess.
#[allow(clippy::too_many_arguments)]
fn propagate_match(
    b_id: StableId,
    matched: &HashMap<StableId, StableId>,
    claimed: &HashSet<StableId>,
    old_by_id: &HashMap<StableId, &Function>,
    new_by_id: &HashMap<StableId, &Function>,
    old_callers: &HashMap<StableId, Vec<StableId>>,
    new_callers: &HashMap<StableId, Vec<StableId>>,
) -> Option<StableId> {
    let b = old_by_id.get(&b_id)?;
    // Images (in `new`) of b's already-matched neighbors.
    let caller_imgs: Vec<StableId> = old_callers
        .get(&b_id)
        .into_iter()
        .flatten()
        .filter_map(|c| matched.get(c).copied())
        .collect();
    let callee_imgs: Vec<StableId> =
        b.callees.iter().filter_map(|c| matched.get(c).copied()).collect();
    if caller_imgs.is_empty() && callee_imgs.is_empty() {
        return None; // not reachable from any confirmed anchor yet
    }
    // Graph-local candidate set: stay on the call edges out of/into the confirmed neighborhood.
    let mut candidates: HashSet<StableId> = HashSet::new();
    for ci in &caller_imgs {
        if let Some(cf) = new_by_id.get(ci) {
            candidates.extend(cf.callees.iter().copied());
        }
    }
    for ei in &callee_imgs {
        if let Some(cs) = new_callers.get(ei) {
            candidates.extend(cs.iter().copied());
        }
    }
    let b_recursive = b.callees.contains(&b_id);
    let (mut best, mut best_s, mut second_s) = (None, -1.0_f64, -1.0_f64);
    for cand in candidates {
        if claimed.contains(&cand) {
            continue;
        }
        let Some(cf) = new_by_id.get(&cand) else { continue };
        let caller_agree = caller_imgs
            .iter()
            .filter(|ci| new_by_id.get(ci).is_some_and(|f| f.callees.contains(&cand)))
            .count();
        let callee_agree = callee_imgs.iter().filter(|ei| cf.callees.contains(ei)).count();
        let recursion = if b_recursive && cf.callees.contains(&cand) { 1.0 } else { 0.0 };
        let s = caller_agree as f64 + callee_agree as f64 + PROP_RECURSION_WEIGHT * recursion;
        if s > best_s {
            second_s = best_s;
            best_s = s;
            best = Some(cand);
        } else if s > second_s {
            second_s = s;
        }
    }
    // The runner-up to beat is the higher of the actual second-best AND the generic-neighbor
    // BASELINE (`PROP_MIN_AGREEMENT`): being one callee of one matched caller is worth the baseline
    // and is shared by ALL of that parent's children — it is not evidence for any *specific* match.
    // So a candidate that merely *is* a neighbor cannot win; the winner must out-score the baseline
    // by the margin, which takes a real discriminator (a self-recursion match, a higher matched
    // in-degree, or calling a matched function). Without this floor, a lone surviving candidate would
    // auto-win even when the true match was inlined away in `new` (a one-directional false positive).
    let runner_up = second_s.max(PROP_MIN_AGREEMENT);
    match best {
        Some(id) if best_s - runner_up >= PROP_MARGIN => Some(id),
        _ => None,
    }
}

/// Weighted cosine of two **BSim** feature vectors (DD-044), in `0..=1`. Each vector is sparse
/// `(feature_hash, weight_bits)` with the weight stored as f32 bits; the producer bakes BSim's
/// feature weights into the coefficients, so this cosine reproduces Ghidra's `LSHVector.compare`
/// exactly. Either side empty → `0` (no BSim signal — the many vectorless functions must NOT all
/// look identical, same discipline as [`jaccard`]/[`cosine`]).
fn bsim_similarity(a: &[(u32, u32)], b: &[(u32, u32)]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let am: HashMap<u32, f64> =
        a.iter().map(|(h, w)| (*h, f64::from(f32::from_bits(*w)))).collect();
    let (mut dot, mut nb) = (0.0, 0.0);
    for (h, w) in b {
        let w = f64::from(f32::from_bits(*w));
        nb += w * w;
        if let Some(aw) = am.get(h) {
            dot += aw * w;
        }
    }
    let na: f64 = a
        .iter()
        .map(|(_, w)| {
            let w = f64::from(f32::from_bits(*w));
            w * w
        })
        .sum();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

/// The old function whose [`bsim_similarity`] to `g` is highest — the reverse direction for the
/// reciprocal-best (symmetric-match) check, mirroring [`best_old_match`]. Vectorless olds are
/// skipped (no signal). `None` if none carry a BSim vector.
fn best_old_match_bsim<'a>(g: &Function, olds: &'a [Function]) -> Option<&'a Function> {
    let mut best: Option<&Function> = None;
    let mut best_s = f64::NEG_INFINITY;
    for o in olds {
        if o.bsim_vector.is_empty() {
            continue;
        }
        let s = bsim_similarity(&o.bsim_vector, &g.bsim_vector);
        if s > best_s {
            best_s = s;
            best = Some(o);
        }
    }
    best
}

/// A BSim vector below this many features is not discriminating enough to anchor an identity — the
/// significance proxy for BSim's "too small to score" filter (mirrors [`ANCHOR_MIN_FEATURES`]).
const BSIM_MIN_FEATURES: usize = 4;
/// A BSim match must clear this weighted-cosine similarity — Ghidra's standard match floor
/// (`CompareExecutablesScript` uses 0.7).
const BSIM_THRESHOLD: f64 = 0.7;
/// ...AND beat the runner-up by this margin — "never guess a near-tie", the fuzzy-space discipline.
/// Reciprocal-best is the load-bearing guard for the symmetric leaves (the one-opcode-apart twin
/// can itself clear the threshold), but the margin is a cheap second line.
const BSIM_MARGIN: f64 = 0.05;

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
    let new_by_id: HashMap<StableId, &Function> =
        new.functions.iter().map(|f| (f.id, f)).collect();
    let old_callers = caller_map(&old.functions);
    let new_callers = caller_map(&new.functions);

    // Build a function MATCHING (old id -> new id) over the functions that carry facts, in fact
    // order so each pass sees the prior passes' claims; then re-target every fact through it. The
    // four passes are strictly increasing in permissiveness, each holding WRONG=0 its own way.
    let mut matched: HashMap<StableId, StableId> = HashMap::new();
    let mut claimed: HashSet<StableId> = HashSet::new();
    let mut targets: Vec<StableId> = Vec::new();
    {
        let mut seen = HashSet::new();
        for f in &old.facts {
            if seen.insert(f.target) {
                targets.push(f.target);
            }
        }
    }

    // Pass 1 — EXACT: a UNIQUE exact-signature match (WRONG=0 by construction). New-side uniqueness
    // only (as before): exactly one new function carries this signature.
    let mut deferred: Vec<StableId> = Vec::new();
    for t in &targets {
        let unique = old_by_id
            .get(t)
            .and_then(|oldf| new_by_sig.get(&signature(oldf)))
            .filter(|ids| ids.len() == 1)
            .map(|ids| ids[0]);
        match unique {
            Some(id) => {
                matched.insert(*t, id);
                claimed.insert(id);
            }
            None => deferred.push(*t),
        }
    }

    // Pass 1.5 — ANCHOR (DD-041): the CROSS-ARCHITECTURE pass. For functions with a rich-enough
    // arch-independent feature set (string literals + import names), match by Jaccard over that set
    // — the signal that survives a different ISA, where exact fingerprint and fuzzy cosine are both
    // ~0. Accepted only on a UNIQUE best clearing ANCHOR_THRESHOLD AND beating the runner-up by
    // ANCHOR_MARGIN. Runs before fuzzy because a unique string/import match is the more reliable
    // signal. WRONG=0 holds — it is a unique-feature match, never a guess.
    let mut deferred2: Vec<StableId> = Vec::new();
    for t in deferred {
        let Some(oldf) = old_by_id.get(&t).copied() else { continue };
        let aset = anchor_set(oldf);
        if aset.len() < ANCHOR_MIN_FEATURES {
            deferred2.push(t); // too few arch-independent features to anchor on — try fuzzy
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
                matched.insert(t, id);
                claimed.insert(id);
            }
            _ => deferred2.push(t),
        }
    }

    // Pass 2 — FUZZY: take the best similarity match among the as-yet-unclaimed new functions — but
    // ONLY if it clears the threshold AND beats the runner-up by the margin AND is RECIPROCAL (the
    // binary-diffing symmetric match): the candidate's OWN best old-match must be this function too.
    // Without reciprocity, a function inlined away in `new` latches onto a structurally-similar stub
    // it happens to share common mnemonics with (small functions have near-identical histograms) — a
    // one-directional false positive; the stub's real reciprocal is its own twin, so it is rejected.
    let mut deferred3: Vec<StableId> = Vec::new();
    for t in deferred2 {
        let Some(oldf) = old_by_id.get(&t).copied() else { continue };
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
        match best {
            Some(nf)
                if best_s >= FUZZY_THRESHOLD
                    && best_s - second_s >= FUZZY_MARGIN
                    && best_old_match(nf, &old.functions).map(|o| o.id) == Some(oldf.id) =>
            {
                matched.insert(t, nf.id);
                claimed.insert(nf.id);
            }
            _ => deferred3.push(t),
        }
    }

    // Pass 3 — PROPAGATION (DD-041 follow-up): spread the confirmed matches along the CALL GRAPH.
    // A function the prior passes couldn't place (a cross-arch arithmetic leaf, say) is matched by
    // its position relative to functions already matched — `fib` is the unique self-recursive callee
    // of the already-anchored `main`. Iterate to a fixpoint: each newly matched function becomes an
    // anchor for its own neighbors. Builds only on WRONG=0 matches and accepts only a unique,
    // margin-clearing graph-context winner, so it never cascades a wrong guess; symmetric leaves
    // (indistinguishable by graph position) stay flagged.
    loop {
        let mut progress = false;
        for t in &deferred3 {
            if matched.contains_key(t) {
                continue;
            }
            if let Some(id) = propagate_match(
                *t, &matched, &claimed, &old_by_id, &new_by_id, &old_callers, &new_callers,
            ) {
                matched.insert(*t, id);
                claimed.insert(id);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }

    // Pass 4 — BSIM (DD-044): the CROSS-ARCHITECTURE lever for the symmetric arithmetic *leaves*
    // that ANCHOR (no strings/imports/callee-names), FUZZY (mnemonic cosine ~0 across ISAs) and
    // PROPAGATION (symmetric graph position) all leave flagged. BSim's decompiler p-code feature
    // vectors abstract the ISA — `factorial` on x86-64 and aarch64 share a (weighted) vector — so a
    // weighted cosine over `bsim_vector` recovers them where every other signal is blind. Accepted
    // only on a UNIQUE best clearing BSIM_THRESHOLD, beating the runner-up by BSIM_MARGIN, AND
    // reciprocal-best (the candidate's own best old-match by BSim is this function) — the same
    // WRONG=0 discipline as the fuzzy pass. The de-risk (DD-044) showed reciprocal-best is
    // load-bearing: the one-opcode-apart twin (`factorial`↔`sum_to`) scores ~0.71, which can clear a
    // bare 0.7 floor, but each true twin is 1.0 so the mutual-best resolves the pair. A too-small
    // vector (< BSIM_MIN_FEATURES) defers (significance proxy). No-op when `bsim_vector` is empty
    // (no producer signal yet), so it never perturbs the string/graph passes or the gate classes.
    for t in &deferred3 {
        if matched.contains_key(t) {
            continue;
        }
        let Some(oldf) = old_by_id.get(t).copied() else { continue };
        if oldf.bsim_vector.len() < BSIM_MIN_FEATURES {
            continue;
        }
        let (mut best, mut best_s, mut second_s): (Option<&Function>, f64, f64) =
            (None, -1.0, -1.0);
        for nf in &new.functions {
            if claimed.contains(&nf.id) || nf.bsim_vector.is_empty() {
                continue;
            }
            let s = bsim_similarity(&oldf.bsim_vector, &nf.bsim_vector);
            if s > best_s {
                second_s = best_s;
                best_s = s;
                best = Some(nf);
            } else if s > second_s {
                second_s = s;
            }
        }
        match best {
            Some(nf)
                if best_s >= BSIM_THRESHOLD
                    && best_s - second_s >= BSIM_MARGIN
                    && best_old_match_bsim(nf, &old.functions).map(|o| o.id) == Some(oldf.id) =>
            {
                matched.insert(*t, nf.id);
                claimed.insert(nf.id);
            }
            _ => {}
        }
    }

    // Re-target every fact through the matching; anything unmatched is flagged, never guessed.
    let mut merged = Vec::new();
    let mut flagged = Vec::new();
    for fact in &old.facts {
        match matched.get(&fact.target) {
            Some(&id) => merged.push(fact.retarget(id)),
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

/// How a matched/changed pair was recovered — the rung of the ladder that placed it, surfaced so a
/// consumer can gauge **confidence**: an `Exact` match is certain; a `Fuzzy` one is a
/// threshold-cleared best-guess. Recorded per `a`-side id in [`ProgramDiff::provenance`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchMethod {
    /// Unique shared structural signature (body unchanged) — the most confident rung.
    Exact,
    /// Call-graph position: a unique neighbourhood of already-matched callers/callees.
    Propagation,
    /// Unique arch-independent features — referenced strings / imports / package-qualified callees.
    Anchor,
    /// Ghidra BSim decompiler-signature feature-vector cosine.
    Bsim,
    /// Mnemonic-mix + ordered-trigram cosine and structural closeness — the soft last resort.
    Fuzzy,
}

impl MatchMethod {
    /// A stable lowercase tag for serialization / display.
    pub fn as_str(self) -> &'static str {
        match self {
            MatchMethod::Exact => "exact",
            MatchMethod::Propagation => "propagation",
            MatchMethod::Anchor => "anchor",
            MatchMethod::Bsim => "bsim",
            MatchMethod::Fuzzy => "fuzzy",
        }
    }
}

/// The recovery of one matched/changed pair: the ladder rung ([`MatchMethod`]) plus a **confidence**
/// percentage (`0..=100`). EXACT and PROPAGATION are structural certainties (100); the feature rungs
/// (ANCHOR / BSIM / FUZZY) carry the actual score that cleared their threshold — so a consumer can
/// report not just HOW a pair matched but how *strongly*. (A percentage, not the raw `f64`, so the
/// diff stays `Eq`/`Hash`-derivable and round-trips exactly.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchInfo {
    pub method: MatchMethod,
    pub confidence: u8,
}

impl MatchInfo {
    /// Build from a rung + a `0.0..=1.0` score, scaling the score to a `0..=100` percentage.
    fn new(method: MatchMethod, score: f64) -> Self {
        MatchInfo {
            method,
            confidence: (score.clamp(0.0, 1.0) * 100.0).round() as u8,
        }
    }
}

/// A structural diff of two programs (the engine behind DD-017's `diff` verb): which functions are
/// matched across them and which live on only one side.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProgramDiff {
    /// `(a_id, b_id)` pairs matched by a UNIQUE shared structural signature (body unchanged).
    pub matched: Vec<(StableId, StableId)>,
    /// `(a_id, b_id)` pairs whose BODY changed (the exact signature differs) but which a later pass
    /// re-identified as the *same* function, modified — by call-graph **propagation**, unique
    /// arch-independent features (**anchor**: strings/imports), Ghidra BSim feature-vector cosine
    /// (**bsim**), or mnemonic-mix similarity (**fuzzy**). Fail-closed: a function with no unique
    /// reciprocal match across every pass stays in `only_a`/`only_b`, never guessed (WRONG=0).
    pub changed: Vec<(StableId, StableId)>,
    /// Stable ids present only in `a` (removed / only-here).
    pub only_a: Vec<StableId>,
    /// Stable ids present only in `b` (added / only-there).
    pub only_b: Vec<StableId>,
    /// How each matched/changed pair was recovered, keyed by the `a`-side id — the ladder rung and a
    /// confidence percentage ([`MatchInfo`]). Every pair in `matched`+`changed` has exactly one entry;
    /// `only_*` have none. Lets a consumer report diff **confidence** without re-running the match.
    pub provenance: Vec<(StableId, MatchInfo)>,
}

/// A function's anchored call-graph neighbourhood: the EXACT-matched callees it calls and callers
/// that call it, both projected into the shared (b-side) id space — its identity to the propagation.
type Neighbourhood = (BTreeSet<StableId>, BTreeSet<StableId>);

/// Index `(id, key)` pairs by key, keeping only keys that occur EXACTLY once (the no-guess rule):
/// an ambiguous neighbourhood — two leftovers with the same anchored neighbours — is dropped, so it
/// can never produce a `changed` match.
fn group_unique(items: &[(StableId, Neighbourhood)]) -> HashMap<Neighbourhood, StableId> {
    let mut counts: HashMap<&Neighbourhood, usize> = HashMap::new();
    for (_, k) in items {
        *counts.entry(k).or_default() += 1;
    }
    items
        .iter()
        .filter(|(_, k)| counts[k] == 1)
        .map(|(id, k)| (k.clone(), *id))
        .collect()
}

/// Record a leftover pairing found by propagation/anchor/fuzzy: an UNCHANGED body (equal signature)
/// is a `matched` the earlier passes missed only on ambiguity; a differing body is `changed`.
fn record_pair(
    diff: &mut ProgramDiff,
    a_fn: &HashMap<StableId, &Function>,
    b_fn: &HashMap<StableId, &Function>,
    aid: StableId,
    bid: StableId,
    method: MatchMethod,
    score: f64,
) {
    if signature(a_fn[&aid]) == signature(b_fn[&bid]) {
        diff.matched.push((aid, bid));
    } else {
        diff.changed.push((aid, bid));
    }
    diff.provenance.push((aid, MatchInfo::new(method, score)));
}

/// The candidate maximising `score`, accepted ONLY if it clears `threshold` AND beats the runner-up
/// by `margin` — the never-guess-a-near-tie rule the exact/anchor/fuzzy/propagation passes all share.
fn best_unique(
    cands: &[StableId],
    score: impl Fn(StableId) -> f64,
    threshold: f64,
    margin: f64,
) -> Option<StableId> {
    let (mut best, mut best_s, mut second_s) = (None, f64::NEG_INFINITY, f64::NEG_INFINITY);
    for &id in cands {
        let s = score(id);
        if s > best_s {
            second_s = best_s;
            best_s = s;
            best = Some(id);
        } else if s > second_s {
            second_s = s;
        }
    }
    best.filter(|_| best_s >= threshold && best_s - second_s >= margin)
}

/// One round of call-graph propagation: pair leftovers whose neighbourhood of already-matched
/// callers/callees is unique on both sides (in the shared id space). Mutates `diff` + the leftovers.
fn propagate_round(
    a: &Program,
    b: &Program,
    a_fn: &HashMap<StableId, &Function>,
    b_fn: &HashMap<StableId, &Function>,
    diff: &mut ProgramDiff,
    left_a: &mut Vec<StableId>,
    left_b: &mut Vec<StableId>,
) {
    let a2b: HashMap<StableId, StableId> =
        diff.matched.iter().chain(diff.changed.iter()).copied().collect();
    let matched_b: HashSet<StableId> = a2b.values().copied().collect();
    let mut a_callers: HashMap<StableId, BTreeSet<StableId>> = HashMap::new();
    for f in &a.functions {
        if let Some(&canon) = a2b.get(&f.id) {
            for c in &f.callees {
                a_callers.entry(*c).or_default().insert(canon);
            }
        }
    }
    let mut b_callers: HashMap<StableId, BTreeSet<StableId>> = HashMap::new();
    for f in &b.functions {
        if matched_b.contains(&f.id) {
            for c in &f.callees {
                b_callers.entry(*c).or_default().insert(f.id);
            }
        }
    }
    let key_a = |id: &StableId| -> Neighbourhood {
        let callees = a_fn[id].callees.iter().filter_map(|c| a2b.get(c).copied()).collect();
        (callees, a_callers.get(id).cloned().unwrap_or_default())
    };
    let key_b = |id: &StableId| -> Neighbourhood {
        let callees =
            b_fn[id].callees.iter().filter(|c| matched_b.contains(c)).copied().collect();
        (callees, b_callers.get(id).cloned().unwrap_or_default())
    };
    let nonempty = |k: &Neighbourhood| !k.0.is_empty() || !k.1.is_empty();
    let a_keys: Vec<(StableId, Neighbourhood)> = left_a.iter().map(|id| (*id, key_a(id))).collect();
    let b_keys: Vec<(StableId, Neighbourhood)> = left_b.iter().map(|id| (*id, key_b(id))).collect();
    let a_by_key = group_unique(&a_keys);
    let b_by_key = group_unique(&b_keys);
    let mut paired_a: HashSet<StableId> = HashSet::new();
    let mut paired_b: HashSet<StableId> = HashSet::new();
    for (id, k) in &a_keys {
        if !nonempty(k) {
            continue;
        }
        let (Some(&ua), Some(&ub)) = (a_by_key.get(k), b_by_key.get(k)) else {
            continue;
        };
        if ua != *id || paired_b.contains(&ub) {
            continue;
        }
        // Propagation is a structural certainty (a unique reciprocal neighbourhood), like exact → 100%.
        record_pair(diff, a_fn, b_fn, *id, ub, MatchMethod::Propagation, 1.0);
        paired_a.insert(*id);
        paired_b.insert(ub);
    }
    left_a.retain(|id| !paired_a.contains(id));
    left_b.retain(|id| !paired_b.contains(id));
}

/// One round of FEATURE matching: pair leftovers by a reciprocal unique best over `score` — ANCHOR
/// (Jaccard of arch-independent features: strings/imports/callee-names) or FUZZY (mnemonic cosine +
/// structure). Both sides are filtered to `eligible` first, so an undiscriminating function (too few
/// features / no mnemonics) does NOT participate — the many feature-poor functions never look alike.
/// Fail-closed: only a reciprocal unique winner clearing `threshold` + `margin` pairs (WRONG=0).
#[allow(clippy::too_many_arguments)]
fn feature_round(
    a_fn: &HashMap<StableId, &Function>,
    b_fn: &HashMap<StableId, &Function>,
    diff: &mut ProgramDiff,
    left_a: &mut Vec<StableId>,
    left_b: &mut Vec<StableId>,
    eligible: impl Fn(&Function) -> bool,
    score: impl Fn(&Function, &Function) -> f64,
    threshold: f64,
    margin: f64,
    method: MatchMethod,
) {
    let a_elig: Vec<StableId> = left_a.iter().copied().filter(|id| eligible(a_fn[id])).collect();
    let b_elig: Vec<StableId> = left_b.iter().copied().filter(|id| eligible(b_fn[id])).collect();
    if a_elig.is_empty() || b_elig.is_empty() {
        return;
    }
    let mut paired_a: HashSet<StableId> = HashSet::new();
    let mut paired_b: HashSet<StableId> = HashSet::new();
    for &aid in &a_elig {
        let Some(bid) =
            best_unique(&b_elig, |bid| score(a_fn[&aid], b_fn[&bid]), threshold, margin)
        else {
            continue;
        };
        if paired_b.contains(&bid) {
            continue;
        }
        // reciprocal-best (symmetric match): `aid` must also be `bid`'s unique best.
        let recip = best_unique(&a_elig, |aid2| score(b_fn[&bid], a_fn[&aid2]), threshold, margin);
        if recip != Some(aid) {
            continue;
        }
        record_pair(diff, a_fn, b_fn, aid, bid, method, score(a_fn[&aid], b_fn[&bid]));
        paired_a.insert(aid);
        paired_b.insert(bid);
    }
    left_a.retain(|id| !paired_a.contains(id));
    left_b.retain(|id| !paired_b.contains(id));
}

/// Structurally diff `a` against `b` — **address-independent**: functions pair by the EXACT-pass
/// signature (CFG size, byte size, out-degree, mnemonic fingerprint), so the diff survives the
/// address shifts a recompile / re-analysis causes (a raw address diff would report everything
/// changed). Only a signature UNIQUE on *both* sides pairs; an ambiguous one is reported on each
/// side rather than guessed — the same no-wrong discipline as the merge. The two programs need not
/// share stable ids (separate materializations), so this is the basis for "git for RE" diff.
///
/// A second **call-graph propagation** pass then recovers *modified* functions: a body change shifts
/// the signature, so a changed function falls out of the exact pass into the leftovers — but if a
/// leftover on each side shares the SAME neighbourhood of exact-matched callers/callees (projected
/// into a shared id space) and that neighbourhood is unique on both sides, it is the same function
/// with an edited body → `changed`. This is the "call-graph propagation from the anchors" the module
/// header names as the next lever. Iterated to a fixpoint (each round's new pairings anchor the
/// next, so a match chains through a freshly-recovered neighbour); fail-closed every round.
pub fn diff_programs(a: &Program, b: &Program) -> ProgramDiff {
    let mut a_by_sig: HashMap<(u32, u64, usize, u64), Vec<StableId>> = HashMap::new();
    for f in &a.functions {
        a_by_sig.entry(signature(f)).or_default().push(f.id);
    }
    let mut b_by_sig: HashMap<(u32, u64, usize, u64), Vec<StableId>> = HashMap::new();
    for f in &b.functions {
        b_by_sig.entry(signature(f)).or_default().push(f.id);
    }
    let mut diff = ProgramDiff::default();
    let mut claimed_b: HashSet<StableId> = HashSet::new();
    let mut left_a: Vec<StableId> = Vec::new();
    for f in &a.functions {
        let sig = signature(f);
        let a_unique = a_by_sig.get(&sig).is_some_and(|ids| ids.len() == 1);
        match b_by_sig.get(&sig) {
            Some(ids) if a_unique && ids.len() == 1 => {
                diff.matched.push((f.id, ids[0]));
                diff.provenance.push((f.id, MatchInfo::new(MatchMethod::Exact, 1.0)));
                claimed_b.insert(ids[0]);
            }
            _ => left_a.push(f.id),
        }
    }
    let mut left_b: Vec<StableId> = b
        .functions
        .iter()
        .map(|f| f.id)
        .filter(|id| !claimed_b.contains(id))
        .collect();

    // --- climb the matching ladder on the leftovers, to a fixpoint --------------------------------
    // The same EXACT → PROPAGATION → ANCHOR → BSIM → FUZZY ladder the merge engine uses, now driving
    // the diff. Each pass's pairings become anchors for the next pass and the next iteration, so a
    // match chains through freshly-recovered neighbours; fixpoint when an iteration adds nothing.
    // Every pass is fail-closed (a unique reciprocal winner clearing threshold + margin, never a
    // guess — WRONG=0). A recovered pair is `matched` if its body is unchanged, `changed` if it differs.
    let a_fn: HashMap<StableId, &Function> = a.functions.iter().map(|f| (f.id, f)).collect();
    let b_fn: HashMap<StableId, &Function> = b.functions.iter().map(|f| (f.id, f)).collect();
    loop {
        let before = diff.matched.len() + diff.changed.len();
        // call-graph propagation: position relative to already-matched callers/callees.
        propagate_round(a, b, &a_fn, &b_fn, &mut diff, &mut left_a, &mut left_b);
        // ANCHOR: unique arch-independent features (strings / imports / package-qualified callees).
        feature_round(
            &a_fn,
            &b_fn,
            &mut diff,
            &mut left_a,
            &mut left_b,
            |f| anchor_set(f).len() >= ANCHOR_MIN_FEATURES,
            |x, y| jaccard(&anchor_set(x), &anchor_set(y)),
            ANCHOR_THRESHOLD,
            ANCHOR_MARGIN,
            MatchMethod::Anchor,
        );
        // BSIM: Ghidra's feature-vector match (weighted cosine over the BSim signature) — the
        // strongest fuzzy signal, so it runs before the cruder mnemonic-mix fallback.
        feature_round(
            &a_fn,
            &b_fn,
            &mut diff,
            &mut left_a,
            &mut left_b,
            |f| f.bsim_vector.len() >= BSIM_MIN_FEATURES,
            |x, y| bsim_similarity(&x.bsim_vector, &y.bsim_vector),
            BSIM_THRESHOLD,
            BSIM_MARGIN,
            MatchMethod::Bsim,
        );
        // FUZZY: mnemonic-mix cosine + structural closeness (the soft last resort).
        feature_round(
            &a_fn,
            &b_fn,
            &mut diff,
            &mut left_a,
            &mut left_b,
            |f| !f.mnemonics.is_empty(),
            similarity,
            FUZZY_THRESHOLD,
            FUZZY_MARGIN,
            MatchMethod::Fuzzy,
        );
        if diff.matched.len() + diff.changed.len() == before {
            break; // fixpoint — no pass recovered anything this iteration
        }
    }
    diff.only_a = left_a;
    diff.only_b = left_b;
    diff
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
    /// Disagreements the confidence rule settled WITHOUT flagging (DD-027): one side's
    /// `Provenance::confidence` cleanly beat the other's (by more than `CONFIDENCE_MARGIN`), so the
    /// higher-confidence fact stands. A near-tie is never auto-resolved — it stays a `conflict`.
    pub resolved_by_confidence: usize,
}

/// The confidence gap (in `Provenance::confidence` points) a disagreement must clear for the
/// higher-confidence fact to win automatically (DD-027). At or under it the two are a near-tie and
/// the disagreement is flagged, never guessed — the same "unique winner clearing a margin" discipline
/// the re-anchoring matcher uses to hold `WRONG = 0`.
const CONFIDENCE_MARGIN: u8 = 5;

/// Merge another analyst's facts into `base` — **git for reverse engineering** (DD-027).
///
/// `incoming` is a *separate materialization of the same binary* (its own stable ids). Each
/// incoming fact is re-anchored onto `base` structurally; clean ones are added, identical ones are
/// no-ops, and a disagreement is settled by `Provenance::confidence` when one side clearly wins
/// (DD-027) — otherwise returned as a [`Conflict`]. `base` is never silently overwritten on a near-tie.
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
    // DD-027: confidence-resolved replacements, applied after the loop (so the merge loop holds no
    // mutable borrow of `base.facts`, mirroring the deferred `to_add`).
    let mut to_replace: Vec<UserFact> = Vec::new();
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
                // DD-027: a disagreement. Settle it by confidence when one side clearly wins; a
                // near-tie (within CONFIDENCE_MARGIN) is flagged, never guessed (WRONG=0 discipline).
                let base_conf = bf.provenance.confidence;
                let incoming_conf = fact.provenance.confidence;
                if incoming_conf > base_conf && incoming_conf - base_conf > CONFIDENCE_MARGIN {
                    // The higher-confidence incoming fact takes over (recorded; deferred swap).
                    to_replace.push(fact.retarget(tid));
                    report.resolved_by_confidence += 1;
                } else if base_conf > incoming_conf && base_conf - incoming_conf > CONFIDENCE_MARGIN {
                    // Base is the clear winner — keep it, drop the lower-confidence incoming.
                    report.resolved_by_confidence += 1;
                } else {
                    conflicts.push(Conflict {
                        target: tid,
                        ours: bf.kind.clone(),
                        theirs: fact.kind.clone(),
                    });
                    report.conflicts += 1;
                }
            }
            Some(_) => {} // identical — the analysts already agree
            None => {
                to_add.push(fact.retarget(tid));
                report.merged += 1;
            }
        }
    }
    base.facts.extend(to_add);
    // Apply the DD-027 confidence-resolved swaps: replace the lower-confidence base fact with the
    // higher-confidence incoming one (same target + kind discriminant).
    for r in to_replace {
        let d = std::mem::discriminant(&r.kind);
        if let Some(slot) = base
            .facts
            .iter_mut()
            .find(|bf| bf.target == r.target && std::mem::discriminant(&bf.kind) == d)
        {
            *slot = r;
        }
    }
    (report, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{FactKind, Provenance};

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

    /// DD-041 propagation: cross-arch, `fib` has NO strings/imports (can't anchor) and ~0 mnemonic
    /// cosine (can't fuzzy-match), but it is the unique self-recursive callee of the anchored `main`
    /// — so call-graph propagation re-anchors it where nothing else could. The non-recursive
    /// arithmetic leaves (gcd/factorial/sum_to) stay orphaned, never mis-attached.
    #[test]
    fn cross_architecture_propagation_recovers_recursive_callee() {
        let mut x86 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let id_of = |p: &Program, n: &str| p.functions.iter().find(|f| f.name == n).unwrap().id;
        let fib = id_of(&x86, "fib");
        let gcd = id_of(&x86, "gcd");
        x86.facts.push(UserFact::new(id_of(&x86, "main"), FactKind::Rename("entry".into())));
        x86.facts.push(UserFact::new(fib, FactKind::Comment("recursive".into())));
        x86.facts.push(UserFact::new(gcd, FactKind::Rename("euclid".into())));

        let mut aarch64 = scylla_ingest::snapshot_to_program(V1_AARCH64).unwrap();
        merge_into(&x86, &mut aarch64);

        let name_on = |marker_pred: &dyn Fn(&FactKind) -> bool| {
            aarch64
                .facts
                .iter()
                .find(|f| marker_pred(&f.kind))
                .map(|f| aarch64.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone())
        };
        // fib re-anchors via propagation (recursion), onto aarch64 fib — zero-wrong.
        let fib_land = name_on(&|k| matches!(k, FactKind::Comment(c) if c == "recursive"));
        assert_eq!(fib_land.as_deref(), Some("fib"), "fib propagates from main across the ISA");
        // gcd (a symmetric non-recursive leaf) is NOT guessed — its marker stays off the new model.
        let gcd_present =
            aarch64.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "euclid"));
        assert!(!gcd_present, "ambiguous leaf gcd must orphan, never mis-attach (WRONG=0)");
    }

    /// DD-044 end-to-end (real data): with the producer now emitting BSim vectors into the
    /// committed snapshots, the symmetric arithmetic leaves `factorial` and `sum_to` — which the
    /// anchor (no strings/imports), fuzzy (mnemonic cosine ~0 cross-ISA) and propagation (symmetric
    /// graph position) passes ALL leave flagged — re-anchor across the ISA via Pass 4 (BSim weighted
    /// cosine). `gcd` (modulo: cross-arch-distinct p-code) stays flagged, fail-closed. Real mathlib
    /// x86-64 -> aarch64, zero-wrong. This is the slice-1 fixture test, now on actual engine output.
    #[test]
    fn cross_architecture_bsim_recovers_leaves_end_to_end() {
        let mut x86 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let id_of = |p: &Program, n: &str| p.functions.iter().find(|f| f.name == n).unwrap().id;
        x86.facts.push(UserFact::new(id_of(&x86, "factorial"), FactKind::Rename("fact".into())));
        x86.facts.push(UserFact::new(id_of(&x86, "sum_to"), FactKind::Rename("sum".into())));
        x86.facts.push(UserFact::new(id_of(&x86, "gcd"), FactKind::Rename("euclid".into())));

        let mut aarch64 = scylla_ingest::snapshot_to_program(V1_AARCH64).unwrap();
        merge_into(&x86, &mut aarch64);

        let name_on = |marker: &str| {
            aarch64
                .facts
                .iter()
                .find(|f| matches!(&f.kind, FactKind::Rename(n) if n == marker))
                .map(|f| {
                    aarch64.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone()
                })
        };
        // factorial + sum_to re-anchor cross-arch via BSim — onto their correctly-named twins, where
        // nothing else could place them (strings/imports/callee-names empty, cosine ~0, leaves).
        assert_eq!(name_on("fact").as_deref(), Some("factorial"), "BSim recovers factorial cross-arch");
        assert_eq!(name_on("sum").as_deref(), Some("sum_to"), "BSim recovers sum_to cross-arch");
        // gcd (modulo) is cross-arch-distinct under BSim too -> stays flagged, never mis-attached.
        assert!(name_on("euclid").is_none(), "gcd stays flagged cross-arch (WRONG=0)");
    }

    /// DD-043: a Go function carries no C strings and no dynamic imports, but its set of
    /// package-qualified CALLEE NAMES is identical across ISAs (pclntab) — so it anchors there too.
    /// Here the two "arches" share callee-names but have DISJOINT mnemonics (cosine = 0) and
    /// different addresses; only the callee-name anchor can carry the fact, and it does — zero-wrong.
    #[test]
    fn callee_names_anchor_recovers_go_function_cross_arch() {
        use scylla_model::{Function, IdMinter};
        let go = |minter: &mut IdMinter, name: &str, mnem: &str, callee_names: Vec<&str>| Function {
            id: minter.mint(),
            addr: 0,
            name: name.into(),
            size: 100,
            bb_count: 3,
            callees: vec![],
            fingerprint: 0,
            mnemonics: vec![(mnem.into(), 5)],
            trigrams: vec![],
            string_refs: vec![],
            imports: vec![],
            callee_names: callee_names.into_iter().map(String::from).collect(),
            bsim_vector: vec![],
            edge_provenance: vec![],
        };
        let prog = |mnem: &str| {
            let mut m = IdMinter::new();
            Program {
                name: "gomath".into(),
                language: "x86:LE:64:default:golang".into(),
                // `main.main` has a rich qualified callee-name set; a noise leaf has none.
                functions: vec![
                    go(&mut m, "main.main", mnem,
                       vec!["fmt.Fprintf", "strconv.Atoi", "runtime.convT64", "main.fib"]),
                    go(&mut m, "runtime.noise", mnem, vec![]),
                ],
                facts: Vec::new(),
            }
        };
        let mut amd64 = prog("MOV"); // x86 mnemonics
        let main_id = amd64.functions.iter().find(|f| f.name == "main.main").unwrap().id;
        amd64.facts.push(UserFact::new(main_id, FactKind::Rename("entry".into())));
        let mut arm64 = prog("ldr"); // aarch64 mnemonics — cosine(amd64,arm64) == 0

        let report = merge_into(&amd64, &mut arm64);
        assert_eq!(report.merged, 1, "main.main re-anchors via its callee-name set, cosine aside");
        let landed = arm64
            .facts
            .iter()
            .find(|f| matches!(&f.kind, FactKind::Rename(n) if n == "entry"))
            .map(|f| arm64.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone());
        assert_eq!(landed.as_deref(), Some("main.main"), "callee-name anchor lands on main.main");
    }

    /// Ordered trigrams add discrimination the order-INDEPENDENT mnemonic histogram can't: two
    /// rebuild candidates with an IDENTICAL instruction multiset (so unigram cosine can't separate
    /// them) but different instruction ORDER. The annotated function's trigrams match one of them —
    /// so the fact re-anchors there, where without trigrams it's a near-tie the fuzzy margin refuses
    /// to guess (fail-closed).
    #[test]
    fn ordered_trigrams_break_a_unigram_tie_and_stay_zero_wrong() {
        use scylla_model::{Function, IdMinter};
        // An isolated leaf: no strings/imports/callee-names/bsim/callees, so exact/anchor/bsim/
        // propagation all defer — the histogram + trigrams come from a real ORDERED stream.
        let leaf = |m: &mut IdMinter, name: &str, seq: &[&str], with_trigrams: bool| Function {
            id: m.mint(),
            addr: 0,
            name: name.into(),
            size: 100,
            bb_count: 5,
            callees: vec![],
            fingerprint: 0,
            mnemonics: scylla_model::mnemonic_histogram(seq),
            trigrams: if with_trigrams {
                scylla_model::mnemonic_trigrams(seq)
            } else {
                vec![]
            },
            string_refs: vec![],
            imports: vec![],
            callee_names: vec![],
            bsim_vector: vec![],
            edge_provenance: vec![],
        };
        // Same multiset, different order — identical histograms, distinct trigrams.
        let target_seq = ["push", "mov", "add", "mov", "ret"];
        let decoy_seq = ["mov", "push", "mov", "add", "ret"];
        assert_eq!(
            scylla_model::mnemonic_histogram(&target_seq),
            scylla_model::mnemonic_histogram(&decoy_seq),
            "fixture: identical histograms -> unigram cosine == 1.0, can't separate them"
        );

        // One annotated OLD function; the rebuild has TWO candidates — one that preserves its
        // instruction order, one that reorders it — with IDENTICAL histograms. The fuzzy margin is
        // measured between the two NEW candidates, so only a signal that separates *them* can place
        // the fact; the unigram cosine ties them, the ordered trigrams don't.
        let run = |with_trigrams: bool| {
            let mut m = IdMinter::new();
            let mut old = Program {
                name: "lib".into(),
                language: "x86:LE:64:default".into(),
                functions: vec![leaf(&mut m, "the_target", &target_seq, with_trigrams)],
                facts: Vec::new(),
            };
            let tid = old.functions[0].id;
            old.facts.push(UserFact::new(tid, FactKind::Rename("KEEP".into())));
            let mut new = Program {
                name: "lib".into(),
                language: "x86:LE:64:default".into(),
                functions: vec![
                    leaf(&mut m, "FUN_same_order", &target_seq, with_trigrams),
                    leaf(&mut m, "FUN_reordered", &decoy_seq, with_trigrams),
                ],
                facts: Vec::new(),
            };
            let report = merge_into(&old, &mut new);
            let landed = new
                .facts
                .iter()
                .find(|f| matches!(&f.kind, FactKind::Rename(n) if n == "KEEP"))
                .map(|f| new.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone());
            (report.merged, landed)
        };

        // WITHOUT trigrams: the two rebuild candidates are indistinguishable (same histogram +
        // structure) — a near-tie the fuzzy margin refuses to guess, so the fact stays flagged.
        let (merged_without, landed_without) = run(false);
        assert_eq!(merged_without, 0, "no trigrams: the tie is flagged, not guessed");
        assert_eq!(landed_without, None);

        // WITH trigrams: the order-preserving candidate's trigrams match the target's, breaking the
        // tie — the rename re-anchors onto it, never onto the reordered decoy (WRONG=0).
        let (merged_with, landed_with) = run(true);
        assert_eq!(merged_with, 1, "trigrams break the tie, the fact re-anchors");
        assert_eq!(
            landed_with.as_deref(),
            Some("FUN_same_order"),
            "the fact lands on the order-preserving rebuild, not the reordered decoy"
        );
    }

    /// DD-044: BSim is the cross-arch lever for the symmetric arithmetic LEAVES nothing else can
    /// place — no strings/imports/callee-names (anchor blind), disjoint mnemonics across ISAs (fuzzy
    /// cosine 0), and no graph position (propagation can't reach them). `factorial` and `sum_to`
    /// differ by one p-code op, so their BSim vectors are near-identical (cosine 0.75) yet each
    /// matches its OWN cross-arch twin at 1.0 — reciprocal-best disambiguates the pair. `gcd`'s
    /// modulo decompiles to a different vector per ISA (cosine 0.25, below threshold), so it stays
    /// flagged (fail-closed). Zero-wrong: recovered facts sit on the correctly-named twins.
    #[test]
    fn bsim_recovers_symmetric_leaves_cross_arch_and_is_zero_wrong() {
        use scylla_model::{Function, IdMinter};
        // Sparse BSim vector from (feature_hash, weight) pairs (weight stored as f32 bits).
        let bv = |pairs: &[(u32, f32)]| -> Vec<(u32, u32)> {
            pairs.iter().map(|(h, w)| (*h, w.to_bits())).collect()
        };
        // An isolated leaf: no strings/imports/callee-names, no callees, ISA-specific mnemonics, a
        // cross-arch-distinct signature — so exact/anchor/fuzzy/propagation all defer to BSim.
        let leaf = |m: &mut IdMinter, name: &str, bb: u32, size: u64, mnem: &str,
                    bsim: Vec<(u32, u32)>| Function {
            id: m.mint(),
            addr: 0,
            name: name.into(),
            size,
            bb_count: bb,
            callees: vec![],
            fingerprint: 0,
            mnemonics: vec![(mnem.into(), 5)],
            trigrams: vec![],
            string_refs: vec![],
            imports: vec![],
            callee_names: vec![],
            bsim_vector: bsim,
            edge_provenance: vec![],
        };
        // factorial vs sum_to share 3 of 4 features (cosine 0.75); gcd's vector is cross-arch-distinct.
        let fact_v = bv(&[(1, 1.0), (2, 1.0), (3, 1.0), (4, 1.0)]);
        let sum_v = bv(&[(1, 1.0), (2, 1.0), (3, 1.0), (5, 1.0)]);
        let gcd_x = bv(&[(6, 1.0), (7, 1.0), (8, 1.0), (9, 1.0)]);
        let gcd_a = bv(&[(6, 1.0), (10, 1.0), (11, 1.0), (12, 1.0)]); // 1/4 = 0.25 vs gcd_x

        let mut mx = IdMinter::new();
        let mut x86 = Program {
            name: "leaves".into(),
            language: "x86:LE:64:default".into(),
            functions: vec![
                leaf(&mut mx, "factorial", 3, 40, "MOV", fact_v.clone()),
                leaf(&mut mx, "sum_to", 3, 42, "MOV", sum_v.clone()),
                leaf(&mut mx, "gcd", 4, 50, "MOV", gcd_x),
            ],
            facts: vec![],
        };
        let id_of = |p: &Program, n: &str| p.functions.iter().find(|f| f.name == n).unwrap().id;
        x86.facts.push(UserFact::new(id_of(&x86, "factorial"), FactKind::Rename("fact".into())));
        x86.facts.push(UserFact::new(id_of(&x86, "sum_to"), FactKind::Rename("sum".into())));
        x86.facts.push(UserFact::new(id_of(&x86, "gcd"), FactKind::Rename("euclid".into())));

        // aarch64: same source, different ISA — distinct sizes/bb + mnemonics (so exact/fuzzy defer),
        // identical BSim vectors for the twins (the ISA-abstracting signal), distinct for gcd.
        let mut ma = IdMinter::new();
        let mut aarch64 = Program {
            name: "leaves".into(),
            language: "AARCH64:LE:64:v8A".into(),
            functions: vec![
                leaf(&mut ma, "factorial", 4, 64, "ldr", fact_v),
                leaf(&mut ma, "sum_to", 4, 66, "ldr", sum_v),
                leaf(&mut ma, "gcd", 5, 70, "ldr", gcd_a),
            ],
            facts: vec![],
        };

        let report = merge_into(&x86, &mut aarch64);
        // factorial + sum_to recover via BSim; gcd flags (fail-closed).
        assert_eq!(report.merged, 2, "BSim recovers the two accumulator leaves cross-arch");
        assert_eq!(report.flagged, 1, "gcd (cross-arch-distinct vector) stays flagged");
        let name_on = |marker: &str| {
            aarch64
                .facts
                .iter()
                .find(|f| matches!(&f.kind, FactKind::Rename(n) if n == marker))
                .map(|f| {
                    aarch64.functions.iter().find(|fn_| fn_.id == f.target).unwrap().name.clone()
                })
        };
        // zero-wrong: each recovered fact sits on its correctly-named twin.
        assert_eq!(name_on("fact").as_deref(), Some("factorial"));
        assert_eq!(name_on("sum").as_deref(), Some("sum_to"));
        // gcd's marker did NOT carry (fail-closed) — never mis-attached to a leaf look-alike.
        assert!(name_on("euclid").is_none(), "gcd must flag, never mis-attach (WRONG=0)");
    }

    /// DD-017 `diff`: `diff_programs` pairs functions by STRUCTURAL signature, not address — so a
    /// re-analysis (fresh ids, same binary) re-pairs every user function, matched pairs are always
    /// the same-named function (no-wrong), and a function new in v2 (`lcm`) shows up only on the v2
    /// side rather than as a false match.
    #[test]
    fn diff_programs_is_address_independent_and_flags_new_functions() {
        let v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let again = scylla_ingest::snapshot_to_program(V1).unwrap(); // fresh ids, same binary
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        let d = diff_programs(&v1, &again);
        for (a_id, b_id) in &d.matched {
            assert_eq!(name(&v1, *a_id), name(&again, *b_id), "a matched pair must be the same function");
        }
        let matched_names: Vec<String> = d.matched.iter().map(|(a, _)| name(&v1, *a)).collect();
        for fnname in ["gcd", "fib", "factorial", "sum_to", "main"] {
            assert!(matched_names.contains(&fnname.to_string()), "{fnname} should pair with itself");
        }
        // The edit (v2 inserts `lcm`): lcm is new, so it lands only on the v2 side.
        let v2 = scylla_ingest::snapshot_to_program(V2).unwrap();
        let d2 = diff_programs(&v1, &v2);
        let only_b: Vec<String> = d2.only_b.iter().map(|id| name(&v2, *id)).collect();
        assert!(only_b.contains(&"lcm".to_string()), "lcm is new in v2 -> only_b");
    }

    /// DD-017 `diff`, call-graph propagation (the module header's "next lever"): a function whose
    /// BODY changed falls out of the exact pass (its signature shifts), but its anchored call-graph
    /// neighbourhood (unchanged callers/callees) re-identifies it — reported as `changed` (the same
    /// function, modified), NOT as a spurious remove+add.
    #[test]
    fn diff_programs_detects_a_modified_body_via_call_graph_propagation() {
        let v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap(); // same binary, fresh ids…
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        // …except gcd's body is edited: bump CFG/size/fingerprint so its EXACT signature differs,
        // but leave its call edges intact so the call-graph neighbourhood is preserved.
        {
            let g = v2.functions.iter_mut().find(|f| f.name == "gcd").unwrap();
            g.bb_count += 3;
            g.size += 64;
            g.fingerprint ^= 0xA5A5;
        }
        let d = diff_programs(&v1, &v2);
        assert_eq!(d.changed.len(), 1, "exactly gcd is modified");
        let (ca, cb) = d.changed[0];
        assert_eq!(name(&v1, ca), "gcd");
        assert_eq!(name(&v2, cb), "gcd", "no-wrong: the modified pair is the same function");
        // gcd is reported ONCE, as changed — never double-counted as removed + added.
        assert!(!d.only_a.iter().any(|id| name(&v1, *id) == "gcd"));
        assert!(!d.only_b.iter().any(|id| name(&v2, *id) == "gcd"));
        // everything else still exact-matched.
        for n in ["main", "fib", "factorial", "sum_to"] {
            assert!(d.matched.iter().any(|(a, _)| name(&v1, *a) == n), "{n} exact-matched");
        }
    }

    /// The diff records HOW each pair was recovered ([`MatchMethod`]) so a consumer can gauge
    /// confidence: the unchanged functions match EXACT, the body-edited gcd is recovered by call-graph
    /// PROPAGATION. Every matched/changed pair gets exactly one provenance entry.
    #[test]
    fn diff_records_match_provenance_per_pair() {
        let v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        {
            let g = v2.functions.iter_mut().find(|f| f.name == "gcd").unwrap();
            g.bb_count += 3;
            g.size += 64;
            g.fingerprint ^= 0xA5A5;
        }
        let d = diff_programs(&v1, &v2);
        assert_eq!(
            d.provenance.len(),
            d.matched.len() + d.changed.len(),
            "exactly one method per matched/changed pair"
        );
        let info_of = |fn_name: &str| -> Option<MatchInfo> {
            d.provenance.iter().find(|(aid, _)| name(&v1, *aid) == fn_name).map(|(_, i)| *i)
        };
        // gcd's body changed but its call edges held -> recovered by call-graph propagation (a
        // structural certainty, so 100% confidence).
        assert_eq!(info_of("gcd").map(|i| i.method), Some(MatchMethod::Propagation), "gcd via propagation");
        assert_eq!(info_of("gcd").map(|i| i.confidence), Some(100), "propagation is certain");
        // the untouched functions matched on their exact signature.
        for n in ["main", "fib", "factorial", "sum_to"] {
            assert_eq!(info_of(n).map(|i| i.method), Some(MatchMethod::Exact), "{n} via exact");
            assert_eq!(info_of(n).map(|i| i.confidence), Some(100), "exact is certain");
        }
    }

    #[test]
    fn match_info_scales_a_score_to_a_confidence_percentage() {
        // The feature-rung score (0.0..=1.0) becomes a 0..=100 percentage; certainties are 100.
        assert_eq!(MatchInfo::new(MatchMethod::Exact, 1.0).confidence, 100);
        assert_eq!(MatchInfo::new(MatchMethod::Fuzzy, 0.87).confidence, 87);
        assert_eq!(MatchInfo::new(MatchMethod::Bsim, 0.755).confidence, 76, "rounds");
        assert_eq!(MatchInfo::new(MatchMethod::Anchor, 0.0).confidence, 0);
        // out-of-range scores clamp into 0..=100 (never a panicking cast).
        assert_eq!(MatchInfo::new(MatchMethod::Fuzzy, 1.5).confidence, 100);
        assert_eq!(MatchInfo::new(MatchMethod::Fuzzy, -0.2).confidence, 0);
    }

    /// Multi-round propagation: when a changed function's sole anchor ALSO changed, round 1 recovers
    /// the anchor (main, via its OTHER matched callees) and round 2 then recovers the dependent (gcd,
    /// now that main is itself an anchor). Both end up `changed` — propagation chains through fresh
    /// matches, recovering what a single round could not.
    #[test]
    fn diff_propagation_chains_through_freshly_matched_anchors() {
        let v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        {
            let m = v2.functions.iter_mut().find(|f| f.name == "main").unwrap();
            m.bb_count += 2;
            m.size += 32;
            m.fingerprint ^= 0x1234;
            let g = v2.functions.iter_mut().find(|f| f.name == "gcd").unwrap();
            g.bb_count += 3;
            g.size += 64;
            g.fingerprint ^= 0xA5A5;
        }
        let d = diff_programs(&v1, &v2);
        let changed: Vec<String> = d.changed.iter().map(|(a, _)| name(&v1, *a)).collect();
        // main recovered in round 1 (anchored by fib/factorial/sum_to)…
        assert!(changed.contains(&"main".to_string()), "main recovered (round 1)");
        // …then gcd recovered in round 2, now that main is an anchor (single round could not).
        assert!(changed.contains(&"gcd".to_string()), "gcd recovered (round 2, chained off main)");
        assert!(!d.only_a.iter().any(|id| name(&v1, *id) == "gcd"));
        assert!(!d.only_b.iter().any(|id| name(&v2, *id) == "gcd"));
    }

    /// Fail-closed across the WHOLE ladder: a function changed past EVERY discriminator is never
    /// guessed (WRONG=0). gcd's body is edited (exact fails), it gains a call to `fib` so its
    /// neighbourhood differs (propagation fails), it has no strings/imports (anchor can't), and its
    /// mnemonic mix is wiped (fuzzy can't) — so it is left in only_a/only_b, never matched.
    #[test]
    fn diff_never_guesses_a_function_changed_past_every_discriminator() {
        let v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        let fib_id = v2.functions.iter().find(|f| f.name == "fib").unwrap().id;
        {
            let g = v2.functions.iter_mut().find(|f| f.name == "gcd").unwrap();
            g.bb_count += 3;
            g.size += 64;
            g.fingerprint ^= 0xA5A5;
            g.callees.push(fib_id); // neighbourhood now differs from gcd-in-v1 → propagation can't
            g.mnemonics.clear(); // no instruction mix → mnemonic-fuzzy can't (gcd has no strings)
            g.bsim_vector.clear(); // no BSim vector → the feature-vector pass can't either
        }
        let d = diff_programs(&v1, &v2);
        assert!(
            !d.changed.iter().any(|(a, _)| name(&v1, *a) == "gcd"),
            "gcd not guessed — changed past every discriminator"
        );
        assert!(d.only_a.iter().any(|id| name(&v1, *id) == "gcd"));
        assert!(d.only_b.iter().any(|id| name(&v2, *id) == "gcd"));
    }

    /// ANCHOR pass: an ISOLATED function (no call edges → propagation can't) with NO mnemonics
    /// (fuzzy can't) but a unique pair of string refs in both builds is re-identified by its
    /// arch-independent features alone — the binary-diffing anchor (BinDiff/SIGMADIFF).
    #[test]
    fn diff_anchor_pass_matches_by_unique_features() {
        let mut v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        let mut iso = v1.functions[0].clone();
        iso.name = "string_keyed".into();
        iso.callees.clear();
        iso.imports.clear();
        iso.callee_names.clear();
        iso.mnemonics.clear(); // deny fuzzy
        iso.string_refs = vec!["unique_marker_alpha".into(), "unique_marker_beta".into()];
        let mut iso1 = iso.clone();
        iso1.id = StableId(9_000_001);
        iso1.bb_count = 5;
        iso1.size = 100;
        iso1.fingerprint = 0x1111;
        let mut iso2 = iso;
        iso2.id = StableId(9_000_002);
        iso2.bb_count = 40; // a different body → exact + structure differ
        iso2.size = 900;
        iso2.fingerprint = 0x2222;
        v1.functions.push(iso1);
        v2.functions.push(iso2);
        let d = diff_programs(&v1, &v2);
        assert!(
            d.changed
                .iter()
                .any(|(x, y)| name(&v1, *x) == "string_keyed" && name(&v2, *y) == "string_keyed"),
            "anchor pass should re-identify the string-keyed function by its features"
        );
        assert!(!d.only_a.iter().any(|id| name(&v1, *id) == "string_keyed"));
        assert!(!d.only_b.iter().any(|id| name(&v2, *id) == "string_keyed"));
    }

    /// FUZZY pass: an isolated function (propagation can't) with NO strings/imports (anchor can't)
    /// but a near-identical mnemonic mix across builds is re-identified by cosine + structure — the
    /// soft last resort, still threshold + margin + reciprocal (WRONG=0).
    #[test]
    fn diff_fuzzy_pass_matches_by_mnemonic_mix() {
        let mut v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        let mut iso = v1.functions[0].clone();
        iso.name = "mnemonic_keyed".into();
        iso.callees.clear();
        iso.imports.clear();
        iso.callee_names.clear();
        iso.string_refs.clear(); // deny anchor
        iso.mnemonics = vec![("mov".into(), 20), ("add".into(), 12), ("cmp".into(), 7)];
        let mut iso1 = iso.clone();
        iso1.id = StableId(9_000_011);
        iso1.bb_count = 6;
        iso1.size = 120;
        iso1.fingerprint = 0xAAAA;
        let mut iso2 = iso;
        iso2.id = StableId(9_000_012);
        iso2.bb_count = 30; // different body → exact fails
        iso2.size = 800;
        iso2.fingerprint = 0xBBBB;
        v1.functions.push(iso1);
        v2.functions.push(iso2);
        let d = diff_programs(&v1, &v2);
        assert!(
            d.changed
                .iter()
                .any(|(x, y)| name(&v1, *x) == "mnemonic_keyed" && name(&v2, *y) == "mnemonic_keyed"),
            "fuzzy pass should re-identify by mnemonic mix"
        );
        assert!(!d.only_a.iter().any(|id| name(&v1, *id) == "mnemonic_keyed"));
        assert!(!d.only_b.iter().any(|id| name(&v2, *id) == "mnemonic_keyed"));
    }

    /// BSIM pass: an isolated function (propagation can't), with no strings (anchor can't) and NO
    /// mnemonics (mnemonic-fuzzy can't), but a near-identical Ghidra BSim feature vector across both
    /// builds — re-identified by weighted cosine, the strongest fuzzy signal (threshold 0.7 + margin
    /// + reciprocal). Proves the diff climbs the LAST rung of the merge engine's matching ladder.
    #[test]
    fn diff_bsim_pass_matches_by_feature_vector() {
        let mut v1 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut v2 = scylla_ingest::snapshot_to_program(V1).unwrap();
        let name =
            |p: &Program, id: StableId| p.functions.iter().find(|f| f.id == id).unwrap().name.clone();
        let mut iso = v1.functions[0].clone();
        iso.name = "vector_keyed".into();
        iso.callees.clear();
        iso.imports.clear();
        iso.callee_names.clear();
        iso.string_refs.clear(); // deny anchor
        iso.mnemonics.clear(); // deny mnemonic-fuzzy
        // A BSim feature vector (feature id, f32-bits weight), >= BSIM_MIN_FEATURES entries, identical
        // in both builds → weighted cosine 1.0.
        iso.bsim_vector = vec![
            (10, 1.0f32.to_bits()),
            (20, 2.5f32.to_bits()),
            (30, 0.75f32.to_bits()),
            (40, 1.5f32.to_bits()),
            (50, 3.0f32.to_bits()),
        ];
        let mut iso1 = iso.clone();
        iso1.id = StableId(9_000_021);
        iso1.bb_count = 8;
        iso1.size = 200;
        iso1.fingerprint = 0xC0DE;
        let mut iso2 = iso;
        iso2.id = StableId(9_000_022);
        iso2.bb_count = 33; // different body → exact fails
        iso2.size = 700;
        iso2.fingerprint = 0xF00D;
        v1.functions.push(iso1);
        v2.functions.push(iso2);
        let d = diff_programs(&v1, &v2);
        assert!(
            d.changed
                .iter()
                .any(|(x, y)| name(&v1, *x) == "vector_keyed" && name(&v2, *y) == "vector_keyed"),
            "bsim pass should re-identify by the BSim feature vector"
        );
        assert!(!d.only_a.iter().any(|id| name(&v1, *id) == "vector_keyed"));
        assert!(!d.only_b.iter().any(|id| name(&v2, *id) == "vector_keyed"));
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

    #[test]
    fn collaboration_resolves_disagreement_by_higher_confidence() {
        // base holds a low-confidence engine guess; incoming is a confident user rename (DD-027).
        let mut a = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut b = scylla_ingest::snapshot_to_program(V1).unwrap();
        let a_fib = a.functions.iter().find(|f| f.name == "fib").unwrap().id;
        let b_fib = b.functions.iter().find(|f| f.name == "fib").unwrap().id;
        a.facts.push(UserFact::new(a_fib, FactKind::Rename("fib_guess".into())).with_provenance(
            Provenance { producer: "engine".into(), confidence: 45 },
        ));
        b.facts.push(UserFact::new(b_fib, FactKind::Rename("recursive".into())).with_provenance(
            Provenance { producer: "user".into(), confidence: 100 },
        ));
        let (report, conflicts) = collaborate(&mut a, &b);
        assert_eq!(conflicts.len(), 0, "a clear confidence winner is not a conflict");
        assert_eq!(report.resolved_by_confidence, 1);
        assert!(a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "recursive")));
        assert!(!a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "fib_guess")));
    }

    #[test]
    fn collaboration_base_wins_when_more_confident() {
        // base is the confident user fact; incoming is a low-confidence producer guess.
        let mut a = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut b = scylla_ingest::snapshot_to_program(V1).unwrap();
        let a_fib = a.functions.iter().find(|f| f.name == "fib").unwrap().id;
        let b_fib = b.functions.iter().find(|f| f.name == "fib").unwrap().id;
        a.facts.push(UserFact::new(a_fib, FactKind::Rename("recursive".into())));
        b.facts.push(UserFact::new(b_fib, FactKind::Rename("fib_guess".into())).with_provenance(
            Provenance { producer: "engine".into(), confidence: 40 },
        ));
        let (report, conflicts) = collaborate(&mut a, &b);
        assert_eq!(conflicts.len(), 0, "base clearly more confident — resolved, not flagged");
        assert_eq!(report.resolved_by_confidence, 1);
        // base keeps its confident value; the low-confidence incoming is dropped.
        assert!(a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "recursive")));
        assert!(!a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "fib_guess")));
    }

    #[test]
    fn collaboration_flags_a_near_tie_never_guesses() {
        // 85 vs 90 — a 5-point gap == the margin, NOT over it: a near-tie, still flagged (WRONG=0).
        let mut a = scylla_ingest::snapshot_to_program(V1).unwrap();
        let mut b = scylla_ingest::snapshot_to_program(V1).unwrap();
        let a_fib = a.functions.iter().find(|f| f.name == "fib").unwrap().id;
        let b_fib = b.functions.iter().find(|f| f.name == "fib").unwrap().id;
        a.facts.push(UserFact::new(a_fib, FactKind::Rename("fib_a".into())).with_provenance(
            Provenance { producer: "analyzer_a".into(), confidence: 85 },
        ));
        b.facts.push(UserFact::new(b_fib, FactKind::Rename("fib_b".into())).with_provenance(
            Provenance { producer: "analyzer_b".into(), confidence: 90 },
        ));
        let (report, conflicts) = collaborate(&mut a, &b);
        assert_eq!(report.conflicts, 1, "a near-tie is flagged, never auto-resolved");
        assert_eq!(report.resolved_by_confidence, 0);
        assert_eq!(conflicts.len(), 1);
        assert!(a.facts.iter().any(|f| matches!(&f.kind, FactKind::Rename(n) if n == "fib_a")));
    }
}
