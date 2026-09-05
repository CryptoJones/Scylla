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

// ----------------------------------------------------------------------------------------
// DD-036 — the total artifact loader: the caps.
// Every reader limit is set EXPLICITLY, never left to the capnp library defaults (which can shift
// between releases). The loader never panics, and its memory is bounded BY THE ARTIFACT'S OWN SIZE:
//   * the capnp reader may traverse at most the words the artifact contains (plus the absolute
//     ceiling below) — a legitimate writer never aliases, so a real artifact never traverses more
//     words than it holds, while a zero-size list declaring millions of elements or many pointers
//     aliasing one list is refused by the reader itself;
//   * the native model materialized from it may occupy at most `MAX_DECODE_AMPLIFICATION` times
//     the artifact's byte length — charged BEFORE each allocation, so a small artifact that would
//     decode to gigabytes is refused, never allocated;
//   * nesting is pinned at the conservative default depth (the model is shallow — deeper is hostile);
//   * every string is bounded at decode time (truncated on a char boundary, counted), never copied
//     whole.
// A structurally broken or cap-busting artifact is a `LoadError`; soft faults (dangling refs,
// duplicate ids, over-long strings) are quarantined and counted in the `LoadReport`.
// ----------------------------------------------------------------------------------------

/// Absolute traversal ceiling: words the reader will traverse before refusing (~512 MiB). The
/// effective limit is the smaller of this and the artifact's own word count (see `reader_options`).
pub const MAX_TRAVERSAL_WORDS: usize = 64 * 1024 * 1024;
/// Max pointer-nesting depth.
pub const MAX_NESTING: i32 = 64;
/// A name/comment longer than this is hostile, not data — truncated on load.
pub const MAX_STRING_LEN: usize = 64 * 1024;
/// Decode budget: the native model may occupy at most this many times the artifact's byte length.
/// A legitimate artifact decodes to under 3x (an empty `Function` is the densest case: ~110 encoded
/// bytes for a ~256-byte native struct); a hostile one can only be refused, never allocated. Tested
/// by `densest_legitimate_artifact_fits_the_decode_budget`.
pub const MAX_DECODE_AMPLIFICATION: usize = 8;

fn reader_options(bytes: &[u8]) -> capnp::message::ReaderOptions {
    let mut o = capnp::message::ReaderOptions::new();
    o.traversal_limit_in_words(Some(bytes.len().div_ceil(8).min(MAX_TRAVERSAL_WORDS)));
    o.nesting_limit(MAX_NESTING);
    o
}

fn fact_discriminant(k: &FactKind) -> (u16, &str) {
    match k {
        FactKind::Rename(s) => (0, s),
        FactKind::Retype(s) => (1, s),
        FactKind::Comment(s) => (2, s),
    }
}

fn fact_from_parts(kind: u16, value: String) -> FactKind {
    match kind {
        0 => FactKind::Rename(value),
        1 => FactKind::Retype(value),
        _ => FactKind::Comment(value),
    }
}

/// The longest prefix of `s` of at most `max` bytes that ends on a char boundary (never panics,
/// unlike `str::truncate`-style slicing).
fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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
            let mut ep = fb
                .reborrow()
                .init_edge_provenance(f.edge_provenance.len() as u32);
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

/// Decode-time state: the remaining decode budget and the quarantine report.
struct Decoder {
    /// Native bytes the decoded model may still materialize.
    budget: usize,
    report: LoadReport,
}

impl Decoder {
    fn new(bytes: &[u8]) -> Self {
        Decoder {
            budget: bytes.len().saturating_mul(MAX_DECODE_AMPLIFICATION),
            report: LoadReport::default(),
        }
    }

    /// Charge `bytes` of native allocation against the budget, refusing once the artifact would
    /// decode to more than `MAX_DECODE_AMPLIFICATION` times its own size. The message names only the
    /// policy, never a number derived from the input, so it is stable for a given artifact regardless
    /// of trailing padding (heads forward it verbatim).
    fn charge(&mut self, field: &str, bytes: usize) -> capnp::Result<()> {
        match self.budget.checked_sub(bytes) {
            Some(left) => {
                self.budget = left;
                Ok(())
            }
            None => Err(capnp::Error::failed(format!(
                "artifact {field} would decode to more than {MAX_DECODE_AMPLIFICATION}x the artifact size (DD-036 decode budget)"
            ))),
        }
    }

    /// Materialize a capnp list: charge the whole native allocation up front (declared length x
    /// element size) so a hostile length is refused before anything is allocated, then grow by push —
    /// no untrusted length ever drives a `with_capacity`.
    fn list<L, T>(
        &mut self,
        field: &str,
        list: L,
        mut item: impl FnMut(&mut Self, L::Item) -> capnp::Result<T>,
    ) -> capnp::Result<Vec<T>>
    where
        L: IntoIterator,
        L::IntoIter: ExactSizeIterator,
    {
        let iter = list.into_iter();
        self.charge(field, iter.len().saturating_mul(std::mem::size_of::<T>()))?;
        let mut out = Vec::new();
        for x in iter {
            out.push(item(self, x)?);
        }
        Ok(out)
    }

    /// Materialize a text field, bounded: an over-long string is truncated on a char boundary and
    /// counted (the excess is never copied), and the bytes kept are charged to the budget.
    fn text(&mut self, field: &str, text: capnp::text::Reader<'_>) -> capnp::Result<String> {
        let s = text.to_str()?;
        let s = if s.len() > MAX_STRING_LEN {
            self.report.truncated_strings += 1;
            truncate_str(s, MAX_STRING_LEN)
        } else {
            s
        };
        self.charge(field, s.len())?;
        Ok(s.to_owned())
    }
}

/// Decode the artifact under the reader caps and the decode budget. Structural quarantine (duplicate
/// ids, dangling refs) is `load`'s job; this only bounds what gets materialized.
fn decode_bytes(bytes: &[u8]) -> capnp::Result<(Program, LoadReport)> {
    // Zero-copy: borrow the segments out of the already-in-memory slice instead of allocating owned
    // copies up to the traversal limit. This removes the full-buffer duplication AND refuses the
    // "20-byte artifact declaring a ~511 MiB segment" allocation — flat-slice validates each declared
    // segment against the actual buffer length rather than allocating it (DD-036 "never OOMs").
    let reader =
        capnp::serialize::read_message_from_flat_slice(&mut &bytes[..], reader_options(bytes))?;
    let p = reader.get_root::<model_capnp::program::Reader>()?;
    let mut d = Decoder::new(bytes);

    let name = d.text("name", p.get_name()?)?;
    let language = d.text("language", p.get_language()?)?;
    let functions = d.list("functions", p.get_functions()?, |d, f| {
        Ok(Function {
            id: StableId(f.get_id()),
            addr: f.get_addr(),
            name: d.text("function.name", f.get_name()?)?,
            size: f.get_size(),
            bb_count: f.get_bb_count(),
            callees: d.list("function.callees", f.get_callees()?, |_, c| Ok(StableId(c)))?,
            fingerprint: f.get_fingerprint(),
            mnemonics: d.list("function.mnemonics", f.get_mnemonics()?, |d, mc| {
                Ok((
                    d.text("function.mnemonics", mc.get_mnemonic()?)?,
                    mc.get_count(),
                ))
            })?,
            string_refs: d.list("function.stringRefs", f.get_string_refs()?, |d, s| {
                d.text("function.stringRefs", s?)
            })?,
            imports: d.list("function.imports", f.get_imports()?, |d, s| {
                d.text("function.imports", s?)
            })?,
            callee_names: d.list("function.calleeNames", f.get_callee_names()?, |d, s| {
                d.text("function.calleeNames", s?)
            })?,
            bsim_vector: d.list("function.bsimVector", f.get_bsim_vector()?, |_, bf| {
                Ok((bf.get_hash(), bf.get_weight()))
            })?,
            trigrams: d.list("function.trigrams", f.get_trigrams()?, |d, mc| {
                Ok((
                    d.text("function.trigrams", mc.get_mnemonic()?)?,
                    mc.get_count(),
                ))
            })?,
            // Per-edge provenance (DD-007), additive: an old artifact yields an empty list (capnp
            // default) → no per-edge provenance recorded, exactly right.
            edge_provenance: d.list(
                "function.edgeProvenance",
                f.get_edge_provenance()?,
                |d, e| {
                    Ok(EdgeProvenance {
                        target: StableId(e.get_target()),
                        provenance: Provenance {
                            producer: d.text("function.edgeProvenance", e.get_producer()?)?,
                            confidence: e.get_confidence().min(100), // documented 0..=100
                        },
                    })
                },
            )?,
        })
    })?;
    let facts = d.list("facts", p.get_facts()?, |d, fact| {
        let value = d.text("facts.value", fact.get_value()?)?;
        let author = d.text("facts.author", fact.get_author()?)?;
        let producer = d.text("facts.producer", fact.get_producer()?)?;
        Ok(UserFact {
            target: StableId(fact.get_target()),
            kind: fact_from_parts(fact.get_kind(), value),
            author: (!author.is_empty()).then_some(Principal(author)),
            // Provenance (DD-007), back-compat: an EMPTY producer means a legacy artifact (the
            // field didn't exist) — default to a certain user fact; else trust the stamped values.
            provenance: if producer.is_empty() {
                Provenance::default()
            } else {
                Provenance {
                    producer,
                    confidence: fact.get_confidence().min(100), // documented 0..=100
                }
            },
        })
    })?;

    Ok((
        Program {
            name,
            language,
            functions,
            facts,
        },
        d.report,
    ))
}

/// **The total artifact loader (DD-036)** — the only way in. Decodes under the explicit reader caps
/// and the decode budget (see the caps block above), then validates and *quarantines* soft faults:
/// duplicate ids and dangling callee/fact/edge-provenance refs are dropped, over-long strings were
/// truncated at decode time, and every quarantine is counted in the [`LoadReport`].
///
/// Never panics. Memory is bounded by the artifact's own size: the reader traverses at most the
/// words the artifact contains, and the native model is at most [`MAX_DECODE_AMPLIFICATION`] times
/// its byte length — an artifact that would exceed either is refused as a [`LoadError`] *before*
/// the allocation, not after.
pub fn load(bytes: &[u8]) -> Result<(Program, LoadReport), LoadError> {
    let (mut prog, mut report) =
        decode_bytes(bytes).map_err(|e| LoadError::Decode(e.to_string()))?;

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
        // Per-edge provenance must describe a surviving callee edge; drop dangling entries, counted.
        let callee_set: HashSet<StableId> = func.callees.iter().copied().collect();
        let ep_before = func.edge_provenance.len();
        func.edge_provenance
            .retain(|e| callee_set.contains(&e.target));
        report.dropped_dangling_edge_provenance += ep_before - func.edge_provenance.len();
    }

    let before_facts = prog.facts.len();
    prog.facts.retain(|f| valid_ids.contains(&f.target.0));
    report.dropped_dangling_facts += before_facts - prog.facts.len();

    Ok((prog, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scylla_model::{
        EdgeProvenance, FactKind, Function, IdMinter, Program, Provenance, StableId, UserFact,
    };

    /// Decode through the one public entry, asserting nothing had to be quarantined.
    fn decode(bytes: &[u8]) -> Program {
        let (prog, report) = load(bytes).expect("load");
        assert!(report.clean(), "expected a clean load, got {report:?}");
        prog
    }

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
        let back = decode(&bytes);
        assert_eq!(prog, back, "model artifact must round-trip losslessly");
    }

    #[test]
    fn artifact_is_non_empty_and_reloadable() {
        let bytes = to_bytes(&sample());
        assert!(!bytes.is_empty());
        // A second decode of the same bytes is stable (cacheable artifact, DD-026).
        assert_eq!(decode(&bytes), decode(&bytes));
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
        let back = decode(&to_bytes(&prog));
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
            let mut fns = p.reborrow().init_functions(1);
            let mut fb = fns.reborrow().get(0);
            fb.set_id(42); // the fact's target must resolve or the loader quarantines it
            fb.set_name("FUN_42");
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

        let prog = decode(&bytes);
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
        let back = decode(&to_bytes(&prog));
        let main_back = back
            .functions
            .iter()
            .find(|f| f.name == "main")
            .expect("main back");
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
        p.functions[0]
            .mnemonics
            .push(("Z".repeat(MAX_STRING_LEN + 16), 1));
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert!(
            report.truncated_strings >= 1,
            "the over-long mnemonic must be truncated"
        );
        assert!(prog.functions[0]
            .mnemonics
            .iter()
            .all(|(m, _)| m.len() <= MAX_STRING_LEN));
    }

    #[test]
    fn load_drops_a_fact_with_a_dangling_target() {
        let mut p = sample();
        p.facts.push(UserFact::new(
            StableId(88888),
            FactKind::Comment("ghost".into()),
        ));
        let bytes = to_bytes(&p);
        let (_, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_facts, 1);
    }

    #[test]
    fn load_truncates_program_name_and_trigrams() {
        // The program name/language and the ordered trigrams are untrusted engine output too.
        let mut p = sample();
        p.name = "N".repeat(MAX_STRING_LEN + 8);
        p.functions[0]
            .trigrams
            .push(("T".repeat(MAX_STRING_LEN + 8), 1));
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert!(
            report.truncated_strings >= 2,
            "program name and the trigram are both truncated"
        );
        assert!(prog.name.len() <= MAX_STRING_LEN);
        assert!(prog.functions[0]
            .trigrams
            .iter()
            .all(|(m, _)| m.len() <= MAX_STRING_LEN));
    }

    #[test]
    fn load_drops_dangling_edge_provenance() {
        // An edge-provenance entry whose target is not a surviving callee edge is dropped, counted.
        let mut p = sample();
        p.functions[1].edge_provenance.push(EdgeProvenance {
            target: StableId(99999), // not among main's callees
            provenance: Provenance {
                producer: "ghidra".into(),
                confidence: 90,
            },
        });
        let bytes = to_bytes(&p);
        let (prog, report) = load(&bytes).expect("load");
        assert_eq!(report.dropped_dangling_edge_provenance, 1);
        assert!(prog.functions[1]
            .edge_provenance
            .iter()
            .all(|e| e.target != StableId(99999)));
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
        assert!(matches!(
            load(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            Err(LoadError::Decode(_))
        ));
        assert!(load(&[]).is_err());
    }

    // --- DD-036: the caps. A hostile writer is not the capnp builder (which cannot alias a pointer
    // or declare a list it never wrote), so these artifacts are assembled word by word. ---

    /// A single-segment artifact assembled from raw words.
    struct Forge {
        words: Vec<u64>,
    }

    impl Forge {
        const VOID: u64 = 0;
        const BYTE: u64 = 2;
        const INLINE_COMPOSITE: u64 = 7;

        fn push(&mut self, w: u64) -> usize {
            self.words.push(w);
            self.words.len() - 1
        }

        fn offset(at: usize, target: usize) -> u64 {
            ((target as i64 - at as i64 - 1) as u32 & 0x3fff_ffff) as u64
        }

        /// A struct pointer at word `at` to a struct at `target` of `data` + `ptrs` words.
        fn struct_ptr(at: usize, target: usize, data: u16, ptrs: u16) -> u64 {
            (Self::offset(at, target) << 2) | ((data as u64) << 32) | ((ptrs as u64) << 48)
        }

        /// A list pointer at word `at` to `target`; `count` is the element count, or the word
        /// count for an inline-composite list.
        fn list_ptr(at: usize, target: usize, elem: u64, count: u64) -> u64 {
            1 | (Self::offset(at, target) << 2) | (elem << 32) | (count << 35)
        }

        /// The tag word of an inline-composite list: a struct pointer whose offset is the count.
        fn tag(count: u64, data: u16, ptrs: u16) -> u64 {
            (count << 2) | ((data as u64) << 32) | ((ptrs as u64) << 48)
        }

        /// A Program root (0 data, 4 pointers: name, language, functions, facts). Returns the
        /// forge and the word indices of the `functions` and `facts` pointers.
        fn program() -> (Forge, usize, usize) {
            let mut f = Forge { words: Vec::new() };
            f.push(Forge::struct_ptr(0, 1, 0, 4));
            f.push(0);
            f.push(0);
            let functions = f.push(0);
            let facts = f.push(0);
            (f, functions, facts)
        }

        fn bytes(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(8 + self.words.len() * 8);
            out.extend_from_slice(&0u32.to_le_bytes()); // segment count - 1
            out.extend_from_slice(&(self.words.len() as u32).to_le_bytes());
            for w in &self.words {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out
        }
    }

    fn function_struct_size() -> (u16, u16) {
        use capnp::traits::HasStructSize;
        let s = <model_capnp::function::Builder<'_> as HasStructSize>::STRUCT_SIZE;
        (s.data, s.pointers)
    }

    /// A functions list of `k` hand-laid Function structs (ids 1..=k, all other fields zero) whose
    /// LAST pointer field (edgeProvenance, ordinal 13) is `alias`: `None` for null, or
    /// `Some(m)` to point every function at ONE shared Byte list of `m` elements.
    fn forge_functions(k: usize, alias: Option<usize>) -> Vec<u8> {
        let (data, ptrs) = function_struct_size();
        let (mut f, functions, _) = Forge::program();
        let per = (data + ptrs) as usize;
        let list = f.push(0);
        f.words[functions] =
            Forge::list_ptr(functions, list, Forge::INLINE_COMPOSITE, (k * per) as u64);
        f.words[list] = Forge::tag(k as u64, data, ptrs);
        let first = f.words.len();
        for i in 0..k {
            f.push(i as u64 + 1); // id
            for _ in 1..per {
                f.push(0);
            }
        }
        if let Some(m) = alias {
            let shared = f.words.len();
            for _ in 0..m.div_ceil(8) {
                f.push(0);
            }
            for i in 0..k {
                let at = first + i * per + per - 1;
                f.words[at] = Forge::list_ptr(at, shared, Forge::BYTE, m as u64);
            }
        }
        f.bytes()
    }

    #[test]
    fn forged_artifacts_decode_when_honest() {
        // Positive control for the forge: the hand-laid layout is a real artifact.
        let prog = decode(&forge_functions(3, None));
        assert_eq!(
            prog.functions.iter().map(|f| f.id.0).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(prog.functions.iter().all(|f| f.edge_provenance.is_empty()));
        // ...including one that points every function at a shared EMPTY list.
        assert_eq!(decode(&forge_functions(3, Some(0))).functions.len(), 3);
    }

    #[test]
    fn a_list_declaring_more_elements_than_the_artifact_has_words_is_refused() {
        // Fuzz regression (oom-db65c11b…): a Void list costs nothing to declare, so a 92-byte
        // artifact claimed 50,954,240 functions and the old loader grew a Vec until libFuzzer killed
        // it. The reader's traversal limit is now the artifact's own word count, so any count past
        // that is refused by capnp itself — before a single element is materialized.
        for field in [0usize, 1] {
            let (base, functions, facts) = Forge::program();
            let at = [functions, facts][field];
            let words = base.words.len() as u64 + 1;
            for count in [words + 1, 1 << 20, 50_954_240, (1 << 29) - 1] {
                let mut f = Forge {
                    words: base.words.clone(),
                };
                let target = f.push(0);
                f.words[at] = Forge::list_ptr(at, target, Forge::VOID, count);
                assert!(
                    matches!(load(&f.bytes()), Err(LoadError::Decode(_))),
                    "field {field} declaring {count} elements must be refused"
                );
            }
        }
        // (A Void list the artifact CAN back is still refused, by the decode budget this time:
        // zero encoded bytes per element is the amplification the budget exists for. The honest
        // shape — an inline-composite list — is covered by `forged_artifacts_decode_when_honest`.)
    }

    #[test]
    fn the_original_fuzz_fixture_is_refused() {
        // fuzz/artifacts/artifact_loader/oom-db65c11bf5ad3496c3ae224351b058f4103d1cd4, verbatim.
        let fixture: [u8; 92] = [
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x18, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(load(&fixture), Err(LoadError::Decode(_))));
    }

    #[test]
    fn a_byte_list_read_as_a_struct_list_is_refused_by_the_decode_budget() {
        // capnp admits a Byte list where a struct list is expected (each byte becomes a 1-byte
        // struct), charging only its real words — so 4 KiB of bytes would materialize 4,096 native
        // Functions (~1 MiB) from a ~4 KiB artifact. The decode budget refuses that BEFORE the Vec
        // exists, with a message that depends only on policy.
        let (mut f, functions, _) = Forge::program();
        let target = f.words.len();
        for _ in 0..512 {
            f.push(0);
        }
        f.words[functions] = Forge::list_ptr(functions, target, Forge::BYTE, 4096);
        let bytes = f.bytes();
        let Err(LoadError::Decode(err)) = load(&bytes) else {
            panic!("a byte-list-as-functions bomb must be refused");
        };
        assert!(
            err.contains("decode budget"),
            "budget error expected, got: {err}"
        );
        // Trailing padding changes the budget, not the verdict or the text heads forward verbatim.
        let mut padded = bytes.clone();
        padded.extend(std::iter::repeat_n(0u8, 4096));
        assert_eq!(load(&padded), Err(LoadError::Decode(err)));
    }

    #[test]
    fn aliased_nested_lists_are_refused() {
        // Every function points its edgeProvenance at ONE shared 512-element Byte list. One read
        // already breaks the decode budget (512 EdgeProvenance from 64 words); sixteen reads also
        // break the traversal limit (each read is charged, and the artifact holds fewer words than
        // the reads would traverse). Both routes end in a typed error, never an allocation.
        for k in [1usize, 16] {
            assert!(
                matches!(
                    load(&forge_functions(k, Some(512))),
                    Err(LoadError::Decode(_))
                ),
                "{k} function(s) aliasing one 512-byte list must be refused"
            );
        }
    }

    #[test]
    fn densest_legitimate_artifact_fits_the_decode_budget() {
        // The writer has no cap of its own because it needs none: the sparsest thing it can write
        // (empty functions and empty facts — the highest native:encoded ratio the model has) still
        // decodes well inside MAX_DECODE_AMPLIFICATION. If a model change ever breaks this, raise
        // the factor (and this test), don't cap the writer.
        let functions: Vec<Function> = (1..=4000u64)
            .map(|i| Function {
                id: StableId(i),
                addr: 0,
                name: String::new(),
                size: 0,
                bb_count: 0,
                callees: vec![],
                fingerprint: 0,
                mnemonics: vec![],
                trigrams: vec![],
                string_refs: vec![],
                imports: vec![],
                callee_names: vec![],
                bsim_vector: vec![],
                edge_provenance: vec![],
            })
            .collect();
        let facts = functions
            .iter()
            .map(|f| UserFact::new(f.id, FactKind::Comment(String::new())))
            .collect();
        let prog = Program {
            name: String::new(),
            language: String::new(),
            functions,
            facts,
        };
        let bytes = to_bytes(&prog);
        assert_eq!(decode(&bytes), prog);
        let native = prog.functions.len() * std::mem::size_of::<Function>()
            + prog.facts.len() * std::mem::size_of::<UserFact>();
        assert!(
            native * 2 <= bytes.len() * MAX_DECODE_AMPLIFICATION,
            "keep 2x headroom under the budget: {native} native bytes from {} encoded",
            bytes.len()
        );
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
