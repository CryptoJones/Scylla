//! Canonical (de)serialization of the Scylla model to the Cap'n Proto artifact (DD-002/026).
//!
//! The native [`scylla_model::Program`] is the live, mutable in-core form; this module
//! projects it to/from the zero-copy on-disk artifact (DD-002 resolution: the buffer is the
//! *persisted projection*, never the live model).

pub mod model_capnp {
    include!(concat!(env!("OUT_DIR"), "/model_capnp.rs"));
}

use std::collections::HashSet;

use scylla_model::{
    EdgeProvenance, FactKind, Function, Principal, Program, Provenance, StableId, UserFact,
};

fn fact_discriminant(k: &FactKind) -> (u16, &str) {
    match k {
        FactKind::Rename(s) => (0, s),
        FactKind::Retype(s) => (1, s),
        FactKind::Comment(s) => (2, s),
    }
}

fn fact_from_parts(kind: u16, value: &str) -> FactKind {
    match kind {
        0 => FactKind::Rename(value.to_owned()),
        1 => FactKind::Retype(value.to_owned()),
        _ => FactKind::Comment(value.to_owned()),
    }
}

/// Serialize a Program to the canonical Cap'n Proto artifact bytes.
pub fn to_bytes(prog: &Program) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut p = message.init_root::<model_capnp::program::Builder>();
        p.set_name(prog.name.as_str());
        p.set_language(prog.language.as_str());

        let mut fns = p.reborrow().init_functions(prog.functions.len() as u32);
        for (i, f) in prog.functions.iter().enumerate() {
            let mut fb = fns.reborrow().get(i as u32);
            fb.set_id(f.id.0);
            fb.set_addr(f.addr);
            fb.set_name(f.name.as_str());
            fb.set_size(f.size);
            fb.set_bb_count(f.bb_count);
            fb.set_fingerprint(f.fingerprint);
            let mut ms = fb.reborrow().init_mnemonics(f.mnemonics.len() as u32);
            for (j, (m, c)) in f.mnemonics.iter().enumerate() {
                let mut mc = ms.reborrow().get(j as u32);
                mc.set_mnemonic(m.as_str());
                mc.set_count(*c);
            }
            let mut cs = fb.reborrow().init_callees(f.callees.len() as u32);
            for (j, c) in f.callees.iter().enumerate() {
                cs.set(j as u32, c.0);
            }
            let mut srs = fb.reborrow().init_string_refs(f.string_refs.len() as u32);
            for (j, s) in f.string_refs.iter().enumerate() {
                srs.set(j as u32, s.as_str());
            }
            let mut imp = fb.reborrow().init_imports(f.imports.len() as u32);
            for (j, s) in f.imports.iter().enumerate() {
                imp.set(j as u32, s.as_str());
            }
            let mut cn = fb.reborrow().init_callee_names(f.callee_names.len() as u32);
            for (j, s) in f.callee_names.iter().enumerate() {
                cn.set(j as u32, s.as_str());
            }
            let mut bv = fb.reborrow().init_bsim_vector(f.bsim_vector.len() as u32);
            for (j, (h, w)) in f.bsim_vector.iter().enumerate() {
                let mut bf = bv.reborrow().get(j as u32);
                bf.set_hash(*h);
                bf.set_weight(*w);
            }
            let mut tg = fb.reborrow().init_trigrams(f.trigrams.len() as u32);
            for (j, (t, c)) in f.trigrams.iter().enumerate() {
                let mut mc = tg.reborrow().get(j as u32);
                mc.set_mnemonic(t.as_str());
                mc.set_count(*c);
            }
            // Per-edge provenance (DD-007), additive + sparse: empty on legacy models.
            let mut ep = fb.reborrow().init_edge_provenance(f.edge_provenance.len() as u32);
            for (j, e) in f.edge_provenance.iter().enumerate() {
                let mut eb = ep.reborrow().get(j as u32);
                eb.set_target(e.target.0);
                eb.set_producer(e.provenance.producer.as_str());
                eb.set_confidence(e.provenance.confidence);
            }
        }

        let mut facts = p.reborrow().init_facts(prog.facts.len() as u32);
        for (i, fact) in prog.facts.iter().enumerate() {
            let mut fb = facts.reborrow().get(i as u32);
            fb.set_target(fact.target.0);
            let (kind, value) = fact_discriminant(&fact.kind);
            fb.set_kind(kind);
            fb.set_value(value);
            fb.set_author(fact.author.as_ref().map(|p| p.0.as_str()).unwrap_or(""));
            // Provenance (DD-007), additive: always written, so a re-serialized legacy artifact
            // acquires its `user`/100 default and round-trips losslessly thereafter.
            fb.set_producer(fact.provenance.producer.as_str());
            fb.set_confidence(fact.provenance.confidence);
        }
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)
        .expect("writing a capnp message to an in-memory Vec is infallible");
    buf
}

/// Deserialize the canonical artifact bytes back into a native Program.
pub fn from_bytes(bytes: &[u8]) -> capnp::Result<Program> {
    // Zero-copy: borrow the segments out of the already-in-memory slice instead of allocating owned
    // copies up to the traversal limit. This removes the full-buffer duplication AND refuses the
    // "20-byte artifact declaring a ~511 MiB segment" allocation — flat-slice validates each declared
    // segment against the actual buffer length rather than allocating it (DD-036 "never OOMs").
    let reader =
        capnp::serialize::read_message_from_flat_slice(&mut &bytes[..], reader_options())?;
    let p = reader.get_root::<model_capnp::program::Reader>()?;

    let mut functions = Vec::new();
    for f in p.get_functions()?.iter() {
        let mut callees = Vec::new();
        for c in f.get_callees()?.iter() {
            callees.push(StableId(c));
        }
        functions.push(Function {
            id: StableId(f.get_id()),
            addr: f.get_addr(),
            name: f.get_name()?.to_str()?.to_owned(),
            size: f.get_size(),
            bb_count: f.get_bb_count(),
            callees,
            fingerprint: f.get_fingerprint(),
            mnemonics: {
                let mut h = Vec::new();
                for mc in f.get_mnemonics()?.iter() {
                    h.push((mc.get_mnemonic()?.to_str()?.to_owned(), mc.get_count()));
                }
                h
            },
            string_refs: {
                let mut v = Vec::new();
                for s in f.get_string_refs()?.iter() {
                    v.push(s?.to_str()?.to_owned());
                }
                v
            },
            imports: {
                let mut v = Vec::new();
                for s in f.get_imports()?.iter() {
                    v.push(s?.to_str()?.to_owned());
                }
                v
            },
            callee_names: {
                let mut v = Vec::new();
                for s in f.get_callee_names()?.iter() {
                    v.push(s?.to_str()?.to_owned());
                }
                v
            },
            bsim_vector: {
                let mut v = Vec::new();
                for bf in f.get_bsim_vector()?.iter() {
                    v.push((bf.get_hash(), bf.get_weight()));
                }
                v
            },
            trigrams: {
                let mut h = Vec::new();
                for mc in f.get_trigrams()?.iter() {
                    h.push((mc.get_mnemonic()?.to_str()?.to_owned(), mc.get_count()));
                }
                h
            },
            // Per-edge provenance (DD-007), additive: an old artifact yields an empty list (capnp
            // default) → no per-edge provenance recorded, exactly right.
            edge_provenance: {
                let mut v = Vec::new();
                for e in f.get_edge_provenance()?.iter() {
                    v.push(EdgeProvenance {
                        target: StableId(e.get_target()),
                        provenance: Provenance {
                            producer: e.get_producer()?.to_str()?.to_owned(),
                            confidence: e.get_confidence(),
                        },
                    });
                }
                v
            },
        });
    }

    let mut facts = Vec::new();
    for fact in p.get_facts()?.iter() {
        let author = fact.get_author()?.to_str()?;
        facts.push(UserFact {
            target: StableId(fact.get_target()),
            kind: fact_from_parts(fact.get_kind(), fact.get_value()?.to_str()?),
            author: (!author.is_empty()).then(|| Principal(author.to_owned())),
            // Provenance (DD-007), back-compat: an EMPTY producer means a legacy artifact (the
            // field didn't exist) — default to a certain user fact; else trust the stamped values.
            provenance: {
                let producer = fact.get_producer()?.to_str()?;
                if producer.is_empty() {
                    Provenance::default()
                } else {
                    Provenance {
                        producer: producer.to_owned(),
                        confidence: fact.get_confidence(),
                    }
                }
            },
        });
    }

    Ok(Program {
        name: p.get_name()?.to_str()?.to_owned(),
        language: p.get_language()?.to_str()?.to_owned(),
        functions,
        facts,
    })
}

// ----------------------------------------------------------------------------------------
// DD-036 — the total artifact loader.
// Reader limits are set EXPLICITLY, never left to the capnp library defaults (which can shift
// between releases). The loader never panics and never OOMs — a structurally broken artifact is a
// LoadError, and soft faults (dangling refs, over-long strings) are quarantined and counted.
// Nesting is pinned at the conservative default depth; the model is intentionally shallow, so a
// deeper artifact is hostile. The traversal ceiling bounds pointer-amplification.
// ----------------------------------------------------------------------------------------

/// Amplification-bomb ceiling: words the reader will traverse before refusing (~512 MiB).
pub const MAX_TRAVERSAL_WORDS: usize = 64 * 1024 * 1024;
/// Max pointer-nesting depth.
pub const MAX_NESTING: i32 = 64;
/// A name/comment longer than this is hostile, not data — truncated on load.
pub const MAX_STRING_LEN: usize = 64 * 1024;

fn reader_options() -> capnp::message::ReaderOptions {
    let mut o = capnp::message::ReaderOptions::new();
    o.traversal_limit_in_words(Some(MAX_TRAVERSAL_WORDS));
    o.nesting_limit(MAX_NESTING);
    o
}

/// What the loader had to quarantine to keep a hostile or buggy artifact total.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoadReport {
    pub dropped_dangling_callees: usize,
    pub dropped_dangling_facts: usize,
    pub dropped_dangling_edge_provenance: usize,
    pub dropped_duplicate_functions: usize,
    pub truncated_strings: usize,
}

impl LoadReport {
    pub fn clean(&self) -> bool {
        self.dropped_dangling_callees == 0
            && self.dropped_dangling_facts == 0
            && self.dropped_dangling_edge_provenance == 0
            && self.dropped_duplicate_functions == 0
            && self.truncated_strings == 0
    }
}

/// Hard load failure — the artifact is structurally unusable (DD-036 hard-reject).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Decode(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Decode(e) => write!(f, "artifact decode failed: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Truncate a String to at most `max` bytes, on a char boundary (never panics, unlike
/// `String::truncate`). Returns whether it truncated.
fn truncate_to(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

/// **The total artifact loader (DD-036).** Decodes with explicit reader caps, then validates
/// and *quarantines* soft faults — dangling callee/fact refs dropped, over-long strings
/// truncated, every quarantine counted in the [`LoadReport`]. Never panics, never OOMs;
/// cap-busting is refused by the reader limits during decode and surfaces as a [`LoadError`].
pub fn load(bytes: &[u8]) -> Result<(Program, LoadReport), LoadError> {
    let mut prog = from_bytes(bytes).map_err(|e| LoadError::Decode(e.to_string()))?;
    let mut report = LoadReport::default();

    // Duplicate stable ids break the identity invariant (DD-004): downstream `.find(|f| f.id == id)`
    // would silently pick the first and the rest become unreachable. Drop later duplicates, counted.
    let mut seen_ids: HashSet<u64> = HashSet::new();
    let before_funcs = prog.functions.len();
    prog.functions.retain(|f| seen_ids.insert(f.id.0));
    report.dropped_duplicate_functions += before_funcs - prog.functions.len();

    let valid_ids: HashSet<u64> = prog.functions.iter().map(|f| f.id.0).collect();

    for func in &mut prog.functions {
        let before = func.callees.len();
        func.callees.retain(|c| valid_ids.contains(&c.0));
        report.dropped_dangling_callees += before - func.callees.len();
        if truncate_to(&mut func.name, MAX_STRING_LEN) {
            report.truncated_strings += 1;
        }
        // EVERY engine-derived string is untrusted — a hostile/buggy producer can emit an absurd one
        // in any field. Bound mnemonics AND ordered trigrams (the same instruction data), then the
        // string refs / import names / callee names (DD-041, DD-043).
        for (mnem, _) in func.mnemonics.iter_mut().chain(func.trigrams.iter_mut()) {
            if truncate_to(mnem, MAX_STRING_LEN) {
                report.truncated_strings += 1;
            }
        }
        for s in func
            .string_refs
            .iter_mut()
            .chain(func.imports.iter_mut())
            .chain(func.callee_names.iter_mut())
        {
            if truncate_to(s, MAX_STRING_LEN) {
                report.truncated_strings += 1;
            }
        }
        // Per-edge provenance must describe a surviving callee edge; drop dangling entries (counted),
        // then bound the untrusted producer string.
        let callee_set: HashSet<StableId> = func.callees.iter().copied().collect();
        let ep_before = func.edge_provenance.len();
        func.edge_provenance.retain(|e| callee_set.contains(&e.target));
        report.dropped_dangling_edge_provenance += ep_before - func.edge_provenance.len();
        for e in &mut func.edge_provenance {
            if truncate_to(&mut e.provenance.producer, MAX_STRING_LEN) {
                report.truncated_strings += 1;
            }
            e.provenance.confidence = e.provenance.confidence.min(100); // documented 0..=100
        }
    }

    // The top-level program strings are untrusted too.
    if truncate_to(&mut prog.name, MAX_STRING_LEN) {
        report.truncated_strings += 1;
    }
    if truncate_to(&mut prog.language, MAX_STRING_LEN) {
        report.truncated_strings += 1;
    }

    let before_facts = prog.facts.len();
    prog.facts.retain(|f| valid_ids.contains(&f.target.0));
    report.dropped_dangling_facts += before_facts - prog.facts.len();
    for fact in &mut prog.facts {
        let s = match &mut fact.kind {
            FactKind::Rename(s) | FactKind::Retype(s) | FactKind::Comment(s) => s,
        };
        if truncate_to(s, MAX_STRING_LEN) {
            report.truncated_strings += 1;
        }
        // The provenance producer and the author Principal are untrusted strings as well.
        if truncate_to(&mut fact.provenance.producer, MAX_STRING_LEN) {
            report.truncated_strings += 1;
        }
        fact.provenance.confidence = fact.provenance.confidence.min(100); // documented 0..=100
        if let Some(author) = &mut fact.author {
            if truncate_to(&mut author.0, MAX_STRING_LEN) {
                report.truncated_strings += 1;
            }
        }
    }

    Ok((prog, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{
        EdgeProvenance, FactKind, Function, IdMinter, Program, Provenance, StableId, UserFact,
    };

    fn sample() -> Program {
        let mut m = IdMinter::new();
        let gcd = m.mint();
        let main = m.mint();
        Program {
            name: "mathlib".into(),
            language: "x86:LE:64:default".into(),
            functions: vec![
                Function {
                    id: gcd,
                    addr: 0x401156,
                    name: "FUN_00401156".into(),
                    size: 64,
                    bb_count: 4,
                    callees: vec![],
                    fingerprint: 0x1111_2222_3333_4444,
                    mnemonics: vec![("MOV".into(), 2), ("RET".into(), 1)],
                    trigrams: vec![("MOV MOV RET".into(), 1)],
                    string_refs: vec![],
                    imports: vec![],
                    callee_names: vec![],
                    bsim_vector: vec![],
                    edge_provenance: vec![],
                },
                Function {
                    id: main,
                    addr: 0x401249,
                    name: "main".into(),
                    size: 180,
                    bb_count: 4,
                    callees: vec![gcd],
                    fingerprint: 0xAAAA_BBBB_CCCC_DDDD,
                    mnemonics: vec![("CALL".into(), 1), ("PUSH".into(), 3)],
                    trigrams: vec![("CALL PUSH PUSH".into(), 1), ("PUSH PUSH PUSH".into(), 1)],
                    string_refs: vec!["result=%d\n".into()],
                    imports: vec!["printf".into()],
                    callee_names: vec!["main.helper".into()],
                    bsim_vector: vec![(0xDEAD_BEEF, 1.0f32.to_bits()), (0x1234, 0.5f32.to_bits())],
                    edge_provenance: vec![],
                },
            ],
            facts: vec![
                UserFact::new(gcd, FactKind::Rename("gcd".into())),
                UserFact::new(main, FactKind::Comment("entry point".into())),
            ],
        }
    }

    #[test]
    fn round_trips_through_capnp() {
        let prog = sample();
        let bytes = to_bytes(&prog);
        let back = from_bytes(&bytes).expect("decode");
        assert_eq!(prog, back, "model artifact must round-trip losslessly");
    }

    #[test]
    fn artifact_is_non_empty_and_reloadable() {
        let bytes = to_bytes(&sample());
        assert!(!bytes.is_empty());
        // A second decode of the same bytes is stable (cacheable artifact, DD-026).
        assert_eq!(from_bytes(&bytes).unwrap(), from_bytes(&bytes).unwrap());
    }

    #[test]
    fn provenance_round_trips_losslessly() {
        // A non-user producer stamps its own provenance (DD-007); it must survive the artifact.
        let mut prog = sample();
        prog.facts[0] = prog.facts[0].clone().with_provenance(Provenance {
            producer: "engine".into(),
            confidence: 95,
        });
        prog.facts[1] = prog.facts[1].clone().with_provenance(Provenance {
            producer: "matcher:fuzzy".into(),
            confidence: 72,
        });
        let back = from_bytes(&to_bytes(&prog)).expect("decode");
        assert_eq!(back.facts[0].provenance.producer, "engine");
        assert_eq!(back.facts[0].provenance.confidence, 95);
        assert_eq!(back.facts[1].provenance.producer, "matcher:fuzzy");
        assert_eq!(back.facts[1].provenance.confidence, 72);
        assert_eq!(prog, back, "DD-007 provenance round-trips losslessly");
    }

    #[test]
    fn legacy_artifact_without_provenance_loads_as_user() {
        // Hand-build a PRE-DD-007 artifact: a UserFact with target/kind/value/author set but the
        // producer/confidence fields NEVER written, exactly as an old writer left them. It must load
        // with the certain-user default — the additive-evolution back-compat guarantee (DD-002).
        let mut message = capnp::message::Builder::new_default();
        {
            let mut p = message.init_root::<model_capnp::program::Builder>();
            p.set_name("legacy");
            p.set_language("x86:LE:64:default");
            let mut facts = p.reborrow().init_facts(1);
            let mut fb = facts.reborrow().get(0);
            fb.set_target(42);
            fb.set_kind(0); // rename
            fb.set_value("renamed");
            fb.set_author("");
            // producer / confidence DELIBERATELY left unset (a pre-provenance writer).
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &message).unwrap();

        let prog = from_bytes(&bytes).expect("decode legacy");
        assert_eq!(prog.facts.len(), 1);
        assert_eq!(
            prog.facts[0].provenance,
            Provenance::default(),
            "a legacy fact (no producer field) defaults to user/100"
        );
    }

    #[test]
    fn edge_provenance_round_trips() {
        // Mark main's call to gcd as a dynamically-observed edge (DD-007 per-edge), then round-trip.
        let mut prog = sample();
        let gcd_id = prog
            .functions
            .iter()
            .find(|f| f.name == "FUN_00401156")
            .expect("gcd")
            .id;
        let main = prog
            .functions
            .iter_mut()
            .find(|f| f.name == "main")
            .expect("main");
        main.edge_provenance.push(EdgeProvenance {
            target: gcd_id,
            provenance: Provenance {
                producer: "dynamic".into(),
                confidence: 90,
            },
        });
        let back = from_bytes(&to_bytes(&prog)).expect("decode");
        let main_back = back.functions.iter().find(|f| f.name == "main").expect("main back");
        assert_eq!(
            main_back.edge_provenance_of(gcd_id),
            Some(&Provenance {
                producer: "dynamic".into(),
                confidence: 90
            }),
            "per-edge provenance survives the artifact, keyed by callee id"
        );
        assert_eq!(prog, back, "per-edge provenance round-trips losslessly");
    }

    // --- DD-036: the total artifact loader ---

    #[test]
    fn load_accepts_a_clean_artifact() {
        let bytes = to_bytes(&sample());
        let (prog, report) = load(&bytes).expect("load");
        assert!(report.clean(), "a well-formed artifact needs no quarantine");
        assert_eq!(prog, sample());
    }

    #[test]
    fn load_quarantines_a_dangling_callee() {
        let mut p = sample();
        p.functions[1].callees.push(StableId(99999)); // main calls a non-existent function
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_callees, 1);
        assert!(!prog.functions[1].callees.contains(&StableId(99999)));
        assert!(prog.functions[1].callees.contains(&prog.functions[0].id)); // real edge survives
    }

    #[test]
    fn load_truncates_an_over_long_mnemonic() {
        // The mnemonic histogram is untrusted too — an absurd mnemonic string is truncated, counted.
        let mut p = sample();
        p.functions[0].mnemonics.push(("Z".repeat(MAX_STRING_LEN + 16), 1));
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert!(report.truncated_strings >= 1, "the over-long mnemonic must be truncated");
        assert!(prog.functions[0].mnemonics.iter().all(|(m, _)| m.len() <= MAX_STRING_LEN));
    }

    #[test]
    fn load_drops_a_fact_with_a_dangling_target() {
        let mut p = sample();
        p.facts.push(UserFact::new(StableId(88888), FactKind::Comment("ghost".into())));
        let bytes = to_bytes(&p);
        let (_, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_facts, 1);
    }

    #[test]
    fn load_truncates_program_name_and_trigrams() {
        // The program name/language and the ordered trigrams are untrusted engine output too.
        let mut p = sample();
        p.name = "N".repeat(MAX_STRING_LEN + 8);
        p.functions[0].trigrams.push(("T".repeat(MAX_STRING_LEN + 8), 1));
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert!(report.truncated_strings >= 2, "program name and the trigram are both truncated");
        assert!(prog.name.len() <= MAX_STRING_LEN);
        assert!(prog.functions[0].trigrams.iter().all(|(m, _)| m.len() <= MAX_STRING_LEN));
    }

    #[test]
    fn load_drops_dangling_edge_provenance() {
        // An edge-provenance entry whose target is not a surviving callee edge is dropped, counted.
        let mut p = sample();
        p.functions[1].edge_provenance.push(EdgeProvenance {
            target: StableId(99999), // not among main's callees
            provenance: Provenance { producer: "ghidra".into(), confidence: 90 },
        });
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_edge_provenance, 1);
        assert!(prog.functions[1].edge_provenance.iter().all(|e| e.target != StableId(99999)));
    }

    #[test]
    fn load_drops_duplicate_function_ids() {
        // Two functions sharing a stable id violate DD-004 identity; the later one is dropped.
        let mut p = sample();
        let dup_id = p.functions[0].id;
        let mut collider = p.functions[0].clone();
        collider.name = "collider".into();
        p.functions.push(collider);
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_duplicate_functions, 1);
        assert_eq!(prog.functions.iter().filter(|f| f.id == dup_id).count(), 1);
    }

    #[test]
    fn load_is_total_on_garbage() {
        // arbitrary non-capnp bytes -> typed error, never a panic
        assert!(matches!(load(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]), Err(LoadError::Decode(_))));
        assert!(load(&[]).is_err());
    }

    #[test]
    fn load_is_total_on_adversarial_bytes() {
        // DD-039 per-commit replay: truncations + bit-flips of a valid artifact, plus junk.
        // The contract is totality — every input yields Ok or a typed LoadError, never a
        // panic/OOM. (The nightly cargo-fuzz lane explores beyond this fixed corpus.)
        let valid = to_bytes(&sample());
        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8],
            vec![0xffu8; 64],
            b"not a capnp message".to_vec(),
            valid.clone(),
        ];
        for n in [1usize, valid.len() / 2, valid.len().saturating_sub(1)] {
            cases.push(valid[..n.min(valid.len())].to_vec());
        }
        for i in (0..valid.len()).step_by(7) {
            let mut v = valid.clone();
            v[i] ^= 0xff;
            cases.push(v);
        }
        for c in &cases {
            let _ = load(c); // must not panic
        }
    }
}
