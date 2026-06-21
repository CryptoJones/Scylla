//! Canonical (de)serialization of the Scylla model to the Cap'n Proto artifact (DD-002/026).
//!
//! The native [`scylla_model::Program`] is the live, mutable in-core form; this module
//! projects it to/from the zero-copy on-disk artifact (DD-002 resolution: the buffer is the
//! *persisted projection*, never the live model).

pub mod model_capnp {
    include!(concat!(env!("OUT_DIR"), "/model_capnp.rs"));
}

use std::collections::HashSet;

use scylla_model::{FactKind, Function, Principal, Program, StableId, UserFact};

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
            let mut cs = fb.reborrow().init_callees(f.callees.len() as u32);
            for (j, c) in f.callees.iter().enumerate() {
                cs.set(j as u32, c.0);
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
        }
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message).expect("write capnp message");
    buf
}

/// Deserialize the canonical artifact bytes back into a native Program.
pub fn from_bytes(bytes: &[u8]) -> capnp::Result<Program> {
    let reader = capnp::serialize::read_message(&mut &bytes[..], reader_options())?;
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
        });
    }

    let mut facts = Vec::new();
    for fact in p.get_facts()?.iter() {
        let author = fact.get_author()?.to_str()?;
        facts.push(UserFact {
            target: StableId(fact.get_target()),
            kind: fact_from_parts(fact.get_kind(), fact.get_value()?.to_str()?),
            author: (!author.is_empty()).then(|| Principal(author.to_owned())),
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
// Reader limits are set ON PURPOSE; the capnp defaults are a security decision made by
// accident. The loader never panics and never OOMs — a structurally broken artifact is a
// LoadError, and soft faults (dangling refs, over-long strings) are quarantined and counted.
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
    pub truncated_strings: usize,
}

impl LoadReport {
    pub fn clean(&self) -> bool {
        self.dropped_dangling_callees == 0
            && self.dropped_dangling_facts == 0
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

    let valid_ids: HashSet<u64> = prog.functions.iter().map(|f| f.id.0).collect();

    for func in &mut prog.functions {
        let before = func.callees.len();
        func.callees.retain(|c| valid_ids.contains(&c.0));
        report.dropped_dangling_callees += before - func.callees.len();
        if truncate_to(&mut func.name, MAX_STRING_LEN) {
            report.truncated_strings += 1;
        }
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
    }

    Ok((prog, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{FactKind, Function, IdMinter, Program, StableId, UserFact};

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
                },
                Function {
                    id: main,
                    addr: 0x401249,
                    name: "main".into(),
                    size: 180,
                    bb_count: 4,
                    callees: vec![gcd],
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
    fn load_drops_a_fact_with_a_dangling_target() {
        let mut p = sample();
        p.facts.push(UserFact::new(StableId(88888), FactKind::Comment("ghost".into())));
        let bytes = to_bytes(&p);
        let (_, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_facts, 1);
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
