//! `scylla-abtest` — the A/B parity differ behind `abtest/` (see `abtest/README.md`).
//!
//! **The question it answers:** does the model Scylla reports for a binary — materialized through
//! the sandboxed engine-service over gRPC and persisted as a `.scylla` artifact (the *inside* leg)
//! — equal what the engine dist reports when its `analyzeHeadless` is run directly with the same
//! `dump_model.java` post-script (the *outside* leg)? Same engine on both legs, so any delta is the
//! wrapper's fault by construction.
//!
//! Both legs land in the same [`Program`]: the inside leg through `scylla_port::Session::from_artifact`,
//! the outside leg through `scylla_ingest::snapshot_to_program`. This crate reduces each to a
//! [`Canonical`] form — keyed by **entry address**, never by stable id (ids are minted per
//! materialization) and never by program **name** (Scylla imports the bytes under a temp filename,
//! the raw run under the real one; the name is the one field that legitimately differs) — and
//! reports every field that disagrees. Then it repeats the check through the client port's own
//! `functions(Detail)` projection, so the *head-visible* output is proven identical too, not just
//! the model underneath.
//!
//! A [`Report`] never hides a difference: `is_parity()` is true only when *nothing* differs.
//!
//! The DECOMPILATION leg — the `decompile` verb vs the raw engine's own decompiler dump — lives in
//! [`decomp`], with the same discipline (keyed by entry address, byte-exact text, nothing hidden).

pub mod decomp;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use scylla_model::Program;
use scylla_port::{Session, Zoom};
use serde::Serialize;

/// Read a baseline file, transparently gunzipping a `.gz` (the committed legs are gzipped so a
/// Go-sized artifact costs hundreds of KB in the repo instead of megabytes).
pub fn read_maybe_gz(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let raw = std::fs::read(path)?;
    if path.extension().is_some_and(|e| e == "gz") {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut out)?;
        Ok(out)
    } else {
        Ok(raw)
    }
}

/// One function in canonical, address-keyed, id-free form — every field the engine emits and Scylla
/// persists. Program name and stable ids are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalFunction {
    pub name: String,
    pub size: u64,
    pub bb_count: u32,
    /// Callee **entry addresses** (sorted, deduped) — the call graph without ids.
    pub callees: Vec<u64>,
    pub fingerprint: u64,
    pub mnemonics: Vec<(String, u32)>,
    pub trigrams: Vec<(String, u32)>,
    pub string_refs: Vec<String>,
    pub imports: Vec<String>,
    pub callee_names: Vec<String>,
    pub bsim_vector: Vec<(u32, u32)>,
}

/// A whole program in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Canonical {
    pub language: String,
    pub functions: BTreeMap<u64, CanonicalFunction>,
}

impl Canonical {
    /// Reduce a [`Program`] to canonical form. A callee whose id does not resolve to a function in
    /// the same program (impossible for a well-formed artifact, but the loader quarantines rather
    /// than panics) is dropped rather than invented.
    pub fn from_program(p: &Program) -> Self {
        let addr_of: BTreeMap<_, _> = p.functions.iter().map(|f| (f.id, f.addr)).collect();
        let functions = p
            .functions
            .iter()
            .map(|f| {
                let callees: BTreeSet<u64> = f
                    .callees
                    .iter()
                    .filter_map(|c| addr_of.get(c).copied())
                    .collect();
                (
                    f.addr,
                    CanonicalFunction {
                        name: f.name.clone(),
                        size: f.size,
                        bb_count: f.bb_count,
                        callees: callees.into_iter().collect(),
                        fingerprint: f.fingerprint,
                        mnemonics: f.mnemonics.clone(),
                        trigrams: f.trigrams.clone(),
                        string_refs: f.string_refs.clone(),
                        imports: f.imports.clone(),
                        callee_names: f.callee_names.clone(),
                        bsim_vector: f.bsim_vector.clone(),
                    },
                )
            })
            .collect();
        Canonical {
            language: p.language.clone(),
            functions,
        }
    }
}

/// One field that disagrees between the legs, on one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldMismatch {
    pub addr: u64,
    pub name: String,
    pub field: &'static str,
    pub inside: String,
    pub outside: String,
}

/// The parity report for one binary. Empty vectors everywhere = parity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub functions_inside: usize,
    pub functions_outside: usize,
    /// `(inside, outside)` when the SLEIGH language ids differ; `None` when they agree.
    pub language_mismatch: Option<(String, String)>,
    /// Entry addresses present only in the inside leg.
    pub only_inside: Vec<u64>,
    /// Entry addresses present only in the outside leg.
    pub only_outside: Vec<u64>,
    /// Per-field disagreements on functions both legs have.
    pub field_mismatches: Vec<FieldMismatch>,
    /// Disagreements in the client port's `functions(Detail)` projection (what a head shows).
    pub projection_mismatches: Vec<String>,
    /// Functions EXCLUDED from the field/projection checks because the raw engine itself reports
    /// them differently from one run to the next (see [`flaky`]) — listed, never hidden. Only
    /// addresses that actually occur in the compared programs are recorded here.
    pub masked: Vec<MaskedFunction>,
}

/// A function masked out of a comparison as engine-nondeterministic, with the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaskedFunction {
    pub addr: u64,
    pub name: String,
}

impl Report {
    /// True only when the legs agree on every function, every field, and every projected view.
    pub fn is_parity(&self) -> bool {
        self.language_mismatch.is_none()
            && self.only_inside.is_empty()
            && self.only_outside.is_empty()
            && self.field_mismatches.is_empty()
            && self.projection_mismatches.is_empty()
    }
}

fn push_if_ne<T: PartialEq + std::fmt::Debug>(
    out: &mut Vec<FieldMismatch>,
    addr: u64,
    name: &str,
    field: &'static str,
    a: &T,
    b: &T,
) {
    if a != b {
        out.push(FieldMismatch {
            addr,
            name: name.to_string(),
            field,
            inside: format!("{a:?}"),
            outside: format!("{b:?}"),
        });
    }
}

/// Compare the inside (Scylla) and outside (raw engine) programs. Pure: no I/O.
pub fn compare(inside: &Program, outside: &Program) -> Report {
    compare_masked(inside, outside, &BTreeSet::new())
}

/// [`compare`], with the functions at `mask` addresses excluded from the per-field and projection
/// checks. The mask is meant to be DERIVED from the engine's own behaviour ([`flaky`] over several
/// raw runs), never hand-written: a function the engine reports two different ways on two direct
/// runs cannot be evidence about the wrapper either way. Masked functions still count toward the
/// function set (a masked function missing from one leg is still `only_*`) and are listed in
/// [`Report::masked`].
pub fn compare_masked(inside: &Program, outside: &Program, mask: &BTreeSet<u64>) -> Report {
    let a = Canonical::from_program(inside);
    let b = Canonical::from_program(outside);
    let mut r = Report {
        functions_inside: a.functions.len(),
        functions_outside: b.functions.len(),
        ..Report::default()
    };
    if a.language != b.language {
        r.language_mismatch = Some((a.language.clone(), b.language.clone()));
    }
    for (addr, fa) in &a.functions {
        match b.functions.get(addr) {
            None => r.only_inside.push(*addr),
            Some(_) if mask.contains(addr) => r.masked.push(MaskedFunction {
                addr: *addr,
                name: fa.name.clone(),
            }),
            Some(fb) => {
                let m = &mut r.field_mismatches;
                let n = &fa.name;
                push_if_ne(m, *addr, n, "name", &fa.name, &fb.name);
                push_if_ne(m, *addr, n, "size", &fa.size, &fb.size);
                push_if_ne(m, *addr, n, "bb_count", &fa.bb_count, &fb.bb_count);
                push_if_ne(m, *addr, n, "callees", &fa.callees, &fb.callees);
                push_if_ne(m, *addr, n, "fingerprint", &fa.fingerprint, &fb.fingerprint);
                push_if_ne(m, *addr, n, "mnemonics", &fa.mnemonics, &fb.mnemonics);
                push_if_ne(m, *addr, n, "trigrams", &fa.trigrams, &fb.trigrams);
                push_if_ne(m, *addr, n, "string_refs", &fa.string_refs, &fb.string_refs);
                push_if_ne(m, *addr, n, "imports", &fa.imports, &fb.imports);
                push_if_ne(
                    m,
                    *addr,
                    n,
                    "callee_names",
                    &fa.callee_names,
                    &fb.callee_names,
                );
                push_if_ne(m, *addr, n, "bsim_vector", &fa.bsim_vector, &fb.bsim_vector);
            }
        }
    }
    for addr in b.functions.keys() {
        if !a.functions.contains_key(addr) {
            r.only_outside.push(*addr);
        }
    }

    // The head-visible check: project both through the client port at full detail and compare
    // what a consumer would actually see (ids stripped — they are per-materialization).
    r.projection_mismatches = compare_projection(inside, outside, mask);
    r
}

/// Project both programs through `Session::functions(Zoom::Detail)` and diff the id-free views
/// (rows for masked functions are left out on both sides).
fn compare_projection(inside: &Program, outside: &Program, mask: &BTreeSet<u64>) -> Vec<String> {
    let project = |p: &Program| -> Vec<String> {
        let s = Session::open(p.clone());
        let mut rows: Vec<String> = s
            .functions(Zoom::Detail)
            .into_iter()
            .filter(|v| !v.addr.is_some_and(|a| mask.contains(&a)))
            .map(|v| {
                let mut callees = v.callees.unwrap_or_default();
                callees.sort();
                let mut callers = v.callers.unwrap_or_default();
                callers.sort();
                format!(
                    "{:#x}\t{}\t{}\tbb={:?}\tsize={:?}\tcallees={:?}\tcallers={:?}",
                    v.addr.unwrap_or(0),
                    v.name,
                    v.summary,
                    v.bb_count,
                    v.size,
                    callees,
                    callers
                )
            })
            .collect();
        rows.sort();
        rows
    };
    let (ra, rb) = (project(inside), project(outside));
    let sa: BTreeSet<&String> = ra.iter().collect();
    let sb: BTreeSet<&String> = rb.iter().collect();
    let mut out = Vec::new();
    for row in sa.difference(&sb) {
        out.push(format!("inside only: {row}"));
    }
    for row in sb.difference(&sa) {
        out.push(format!("outside only: {row}"));
    }
    out
}

/// One engine-nondeterministic function: its address, the name(s) seen, the fields that varied,
/// and every distinct `(size, bb_count)` the raw engine produced for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlakyFunction {
    pub addr: u64,
    pub names: Vec<String>,
    pub fields: Vec<&'static str>,
    pub variants: Vec<(u64, u32)>,
}

/// The engine-nondeterminism record for one binary, over `runs` direct engine runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Flaky {
    pub runs: usize,
    pub functions: Vec<FlakyRecord>,
}

/// The persisted shape of a [`FlakyFunction`] (addresses as hex strings for readability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct FlakyRecord {
    pub addr: String,
    pub names: Vec<String>,
    pub fields: Vec<String>,
    pub variants: Vec<(u64, u32)>,
}

impl Flaky {
    /// The address mask [`compare_masked`] takes.
    pub fn mask(&self) -> BTreeSet<u64> {
        self.functions
            .iter()
            .filter_map(|f| {
                let t = f.addr.strip_prefix("0x").unwrap_or(&f.addr);
                u64::from_str_radix(t, 16).ok()
            })
            .collect()
    }
}

/// Characterize the ENGINE's own nondeterminism: given several programs produced by running the
/// raw engine directly on the SAME binary, list every function (by address) that any field
/// disagrees on between any two runs. A function only present in some runs is included too
/// (variants record what was seen). This is evidence about the engine, gathered from the engine
/// alone — no Scylla leg is involved — and is the only legitimate source of a comparison mask.
pub fn flaky(runs: &[Program]) -> Flaky {
    let canon: Vec<Canonical> = runs.iter().map(Canonical::from_program).collect();
    let mut addrs: BTreeSet<u64> = BTreeSet::new();
    for c in &canon {
        addrs.extend(c.functions.keys());
    }
    let mut functions = Vec::new();
    for addr in addrs {
        let seen: Vec<&CanonicalFunction> = canon
            .iter()
            .filter_map(|c| c.functions.get(&addr))
            .collect();
        let mut fields: Vec<&'static str> = Vec::new();
        if seen.len() != canon.len() {
            fields.push("presence");
        }
        if let Some(first) = seen.first() {
            let differs = |f: &dyn Fn(&CanonicalFunction) -> bool| seen.iter().any(|x| f(x));
            if differs(&|x| x.name != first.name) {
                fields.push("name");
            }
            if differs(&|x| x.size != first.size) {
                fields.push("size");
            }
            if differs(&|x| x.bb_count != first.bb_count) {
                fields.push("bb_count");
            }
            if differs(&|x| x.callees != first.callees) {
                fields.push("callees");
            }
            if differs(&|x| x.mnemonics != first.mnemonics) {
                fields.push("mnemonics");
            }
            if differs(&|x| x.trigrams != first.trigrams) {
                fields.push("trigrams");
            }
            if differs(&|x| x.string_refs != first.string_refs) {
                fields.push("string_refs");
            }
            if differs(&|x| x.imports != first.imports) {
                fields.push("imports");
            }
            if differs(&|x| x.callee_names != first.callee_names) {
                fields.push("callee_names");
            }
            if differs(&|x| x.bsim_vector != first.bsim_vector) {
                fields.push("bsim_vector");
            }
        }
        if fields.is_empty() {
            continue;
        }
        let names: BTreeSet<String> = seen.iter().map(|x| x.name.clone()).collect();
        let variants: BTreeSet<(u64, u32)> = seen.iter().map(|x| (x.size, x.bb_count)).collect();
        functions.push(FlakyRecord {
            addr: format!("{addr:#x}"),
            names: names.into_iter().collect(),
            fields: fields.iter().map(|f| f.to_string()).collect(),
            variants: variants.into_iter().collect(),
        });
    }
    Flaky {
        runs: runs.len(),
        functions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{Function, IdMinter, StableId};

    fn func(id: StableId, addr: u64, name: &str, callees: Vec<StableId>) -> Function {
        let mn = vec!["PUSH".to_string(), "MOV".to_string(), "RET".to_string()];
        Function {
            id,
            addr,
            name: name.into(),
            size: 16,
            bb_count: 1,
            callees,
            fingerprint: scylla_model::mnemonic_fingerprint(&mn),
            mnemonics: scylla_model::mnemonic_histogram(&mn),
            trigrams: scylla_model::mnemonic_trigrams(&mn),
            string_refs: vec![],
            imports: vec![],
            callee_names: vec![],
            bsim_vector: vec![],
            edge_provenance: vec![],
        }
    }

    fn program(name: &str, skip_ids: u64) -> Program {
        // Mint ids from a different starting point per program: identity must NOT leak into parity.
        let mut m = IdMinter::new();
        for _ in 0..skip_ids {
            m.mint();
        }
        let (a, b) = (m.mint(), m.mint());
        Program {
            name: name.into(),
            language: "x86:LE:64:default".into(),
            functions: vec![
                func(a, 0x401000, "main", vec![b]),
                func(b, 0x401100, "gcd", vec![]),
            ],
            facts: vec![],
        }
    }

    #[test]
    fn same_model_under_different_names_and_ids_is_parity() {
        let inside = program("scylla-bin1234.bin", 0);
        let outside = program("mathlib.elf", 7);
        let r = compare(&inside, &outside);
        assert!(r.is_parity(), "{r:?}");
        assert_eq!(r.functions_inside, 2);
    }

    #[test]
    fn a_changed_field_is_named_by_addr_and_field() {
        let inside = program("a", 0);
        let mut outside = program("b", 0);
        outside.functions[1].bb_count = 3;
        let r = compare(&inside, &outside);
        assert!(!r.is_parity());
        assert_eq!(r.field_mismatches.len(), 1);
        assert_eq!(r.field_mismatches[0].addr, 0x401100);
        assert_eq!(r.field_mismatches[0].field, "bb_count");
        // The port projection sees it too (bb is part of the Detail view).
        assert!(!r.projection_mismatches.is_empty());
    }

    #[test]
    fn a_missing_function_lands_in_only_lists() {
        let inside = program("a", 0);
        let mut outside = program("b", 0);
        outside.functions.pop();
        let r = compare(&inside, &outside);
        assert_eq!(r.only_inside, vec![0x401100]);
        assert!(r.only_outside.is_empty());
        assert!(!r.is_parity());
    }

    #[test]
    fn flaky_lists_only_functions_the_runs_disagree_on() {
        let r1 = program("run1", 0);
        let mut r2 = program("run2", 3);
        r2.functions[1].size = 99; // gcd's extent flipped between two raw runs
        let f = flaky(&[r1.clone(), r2.clone(), r1.clone()]);
        assert_eq!(f.runs, 3);
        assert_eq!(f.functions.len(), 1);
        assert_eq!(f.functions[0].addr, "0x401100");
        assert_eq!(f.functions[0].fields, vec!["size"]);
        assert_eq!(f.functions[0].variants, vec![(16, 1), (99, 1)]);
        assert_eq!(f.mask(), BTreeSet::from([0x401100]));
        // Identical runs -> nothing flaky.
        assert!(flaky(&[r1.clone(), r1]).functions.is_empty());
    }

    #[test]
    fn a_masked_function_is_listed_and_excluded_but_presence_still_counts() {
        let inside = program("a", 0);
        let mut outside = program("b", 0);
        outside.functions[1].bb_count = 3;
        let mask = BTreeSet::from([0x401100]);
        let r = compare_masked(&inside, &outside, &mask);
        assert!(r.is_parity(), "{r:?}");
        assert_eq!(r.masked.len(), 1);
        assert_eq!(r.masked[0].name, "gcd");
        // ...but a masked function MISSING from a leg is still a real difference.
        outside.functions.pop();
        let r = compare_masked(&inside, &outside, &mask);
        assert_eq!(r.only_inside, vec![0x401100]);
        assert!(!r.is_parity());
    }

    #[test]
    fn a_language_mismatch_is_not_parity() {
        let inside = program("a", 0);
        let mut outside = program("b", 0);
        outside.language = "ARM:LE:32:v8".into();
        let r = compare(&inside, &outside);
        assert!(r.language_mismatch.is_some());
        assert!(!r.is_parity());
    }
}
