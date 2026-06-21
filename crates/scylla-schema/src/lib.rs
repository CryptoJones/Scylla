//! Canonical (de)serialization of the Scylla model to the Cap'n Proto artifact (DD-002/026).
//!
//! The native [`scylla_model::Program`] is the live, mutable in-core form; this module
//! projects it to/from the zero-copy on-disk artifact (DD-002 resolution: the buffer is the
//! *persisted projection*, never the live model).

pub mod model_capnp {
    include!(concat!(env!("OUT_DIR"), "/model_capnp.rs"));
}

use scylla_model::{FactKind, Function, Program, StableId, UserFact};

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
        }
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message).expect("write capnp message");
    buf
}

/// Deserialize the canonical artifact bytes back into a native Program.
pub fn from_bytes(bytes: &[u8]) -> capnp::Result<Program> {
    let reader =
        capnp::serialize::read_message(&mut &bytes[..], capnp::message::ReaderOptions::new())?;
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
        facts.push(UserFact {
            target: StableId(fact.get_target()),
            kind: fact_from_parts(fact.get_kind(), fact.get_value()?.to_str()?),
        });
    }

    Ok(Program {
        name: p.get_name()?.to_str()?.to_owned(),
        language: p.get_language()?.to_str()?.to_owned(),
        functions,
        facts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{FactKind, Function, IdMinter, Program, UserFact};

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
                UserFact { target: gcd, kind: FactKind::Rename("gcd".into()) },
                UserFact { target: main, kind: FactKind::Comment("entry point".into()) },
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
}
