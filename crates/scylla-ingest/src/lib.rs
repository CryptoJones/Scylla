//! First materialization path (Sprint 4): a GayHydra headless **snapshot** (the JSON the
//! prototype harness already emits) → the native [`scylla_model::Program`].
//!
//! This is the producer side of the engine-port narrow waist (DD-009) in its simplest form:
//! the heavy JVM engine analyzes a binary out-of-process and hands us a coarse snapshot; we
//! mint stable ids (DD-004), resolve the call graph onto them, and the result serializes to
//! the canonical Cap'n Proto artifact (DD-002/026) via `scylla-schema`.

use std::collections::{HashMap, HashSet};

use scylla_model::{Function, IdMinter, Program, StableId};
use serde::Deserialize;

#[derive(Deserialize)]
struct SnapFunc {
    entry: String,
    name: String,
    size: u64,
    bb_count: u32,
    #[serde(default)]
    callees: Vec<String>,
    /// The function's instruction mnemonics, in order (the engine already emits these). We fold
    /// them into a structural fingerprint (DD-038); absent → no fingerprint (0).
    #[serde(default)]
    mnemonics: Vec<String>,
    /// Arch-independent features (DD-041): referenced string literals and imported call names.
    /// Absent in older snapshots → empty (no cross-arch anchor signal, degrades cleanly).
    #[serde(default)]
    string_refs: Vec<String>,
    #[serde(default)]
    imports: Vec<String>,
    /// Package-qualified callee names (DD-043) — the Go cross-arch anchor signal. Absent in older
    /// snapshots → empty.
    #[serde(default)]
    callee_names: Vec<String>,
    /// BSim LSH feature vector (DD-044): `(feature_hash, f32-weight-bits)` pairs. Absent in older
    /// snapshots and on the cold path → empty (the cross-arch BSim re-anchoring pass simply doesn't
    /// fire), so it degrades cleanly.
    #[serde(default)]
    bsim_vector: Vec<(u32, u32)>,
}

#[derive(Deserialize)]
struct Snapshot {
    program: String,
    language: String,
    functions: Vec<SnapFunc>,
}

/// Parse a hex entry/callee address (`0x401156`, `0X401156`, or bare `401156`) to its numeric value,
/// or `None` when it does not parse. Returning `None` (never a collapsed `0`) is load-bearing: the
/// caller must not conflate an unparseable address with the real address `0`.
fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16).ok()
}

/// Build a native model `Program` from a snapshot JSON string.
pub fn snapshot_to_program(json: &str) -> serde_json::Result<Program> {
    let snap: Snapshot = serde_json::from_str(json)?;
    let mut minter = IdMinter::new();

    // Mint one stable id per function, by INDEX — identity is the minted id, never the address
    // (DD-004). A duplicate or unparseable entry address must never make two functions share an id
    // (the old address-keyed mint did, silently). A separate address->id map drives callee
    // resolution, and it drops ambiguous addresses so an edge resolves to nothing, never to the
    // wrong function.
    let ids: Vec<StableId> = snap.functions.iter().map(|_| minter.mint()).collect();
    let mut addr_to_id: HashMap<u64, StableId> = HashMap::new();
    let mut ambiguous: HashSet<u64> = HashSet::new();
    for (f, &id) in snap.functions.iter().zip(&ids) {
        if let Some(a) = parse_addr(&f.entry) {
            if addr_to_id.insert(a, id).is_some() {
                ambiguous.insert(a); // two functions claim this address — resolution is ambiguous
            }
        }
    }
    for a in &ambiguous {
        addr_to_id.remove(a);
    }

    // Build functions, resolving call edges to stable ids by their (unique) target address.
    let mut functions = Vec::with_capacity(snap.functions.len());
    for (f, &id) in snap.functions.iter().zip(&ids) {
        let addr = parse_addr(&f.entry).unwrap_or(0);
        let callees = f
            .callees
            .iter()
            .filter_map(|c| parse_addr(c).and_then(|ca| addr_to_id.get(&ca).copied()))
            .collect();
        let histogram = scylla_model::mnemonic_histogram(&f.mnemonics);
        functions.push(Function {
            id,
            addr,
            name: f.name.clone(),
            size: f.size,
            bb_count: f.bb_count,
            callees,
            fingerprint: scylla_model::histogram_fingerprint(&histogram),
            // Ordered trigrams from the in-order stream — computed here, before the order is lost to
            // the histogram (the raw stream isn't persisted).
            trigrams: scylla_model::mnemonic_trigrams(&f.mnemonics),
            mnemonics: histogram,
            string_refs: f.string_refs.clone(),
            imports: f.imports.clone(),
            callee_names: f.callee_names.clone(),
            bsim_vector: f.bsim_vector.clone(),
            // The static snapshot producer records no per-edge provenance (DD-007).
            edge_provenance: Vec::new(),
        });
    }

    Ok(Program {
        name: snap.program,
        language: snap.language,
        functions,
        facts: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real GayHydra headless snapshot produced by prototype/harness/snapshot.sh.
    const MATHLIB: &str =
        include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

    #[test]
    fn ingests_a_real_gayhydra_snapshot() {
        let prog = snapshot_to_program(MATHLIB).expect("parse snapshot");
        assert_eq!(prog.name, "mathlib.x86-64.O0.elf");
        let gcd = prog.functions.iter().find(|f| f.name == "gcd").expect("gcd");
        let main = prog.functions.iter().find(|f| f.name == "main").expect("main");
        // main calls gcd: the call edge resolved onto gcd's stable id.
        assert!(main.callees.contains(&gcd.id), "main should call gcd");
        // identity is the minted id, not the address
        assert_ne!(gcd.id, main.id);
    }

    #[test]
    fn materialized_program_round_trips_through_the_artifact() {
        let prog = snapshot_to_program(MATHLIB).unwrap();
        let bytes = scylla_schema::to_bytes(&prog);
        let back = scylla_schema::from_bytes(&bytes).unwrap();
        assert_eq!(prog, back, "materialized model must round-trip losslessly");
    }

    #[test]
    fn duplicate_entry_addresses_get_distinct_ids() {
        // A buggy/compromised engine (GAP-3) could emit two functions with the same entry address.
        // They must get DISTINCT stable ids (identity is the minted id, not the address, DD-004),
        // and a call to that now-ambiguous address must resolve to NOTHING, never the wrong function.
        let json = r#"{"program":"p","language":"l","functions":[
            {"entry":"0x1000","name":"a","size":1,"bb_count":1,"callees":[]},
            {"entry":"0x1000","name":"b","size":1,"bb_count":1,"callees":[]},
            {"entry":"0x2000","name":"caller","size":1,"bb_count":1,"callees":["0x1000"]}
        ]}"#;
        let prog = snapshot_to_program(json).expect("parse");
        let id = |n: &str| prog.functions.iter().find(|f| f.name == n).unwrap().id;
        assert_ne!(id("a"), id("b"), "two functions sharing an entry address must not share an id");
        let caller = prog.functions.iter().find(|f| f.name == "caller").unwrap();
        assert!(caller.callees.is_empty(), "a call to the ambiguous address resolves to nothing");
    }

    #[test]
    fn ingest_is_total_on_malformed_json() {
        // DD-039 per-commit replay: a compromised/buggy engine could emit anything. Parsing
        // must never panic — bad input is an Err, not a crash.
        assert!(snapshot_to_program("").is_err());
        assert!(snapshot_to_program("not json").is_err());
        assert!(snapshot_to_program("{}").is_err());
        for bad in [
            "null",
            "[]",
            "42",
            r#"{"program":"p","language":"l","functions":"nope"}"#,
            r#"{"program":"p","language":"l","functions":[{"entry":"zzz","name":3,"size":1,"bb_count":1}]}"#,
            r#"{"program":"p","language":"l","functions":[{"entry":"deadbeef","name":"f","size":1,"bb_count":1,"callees":[42]}]}"#,
        ] {
            let _ = snapshot_to_program(bad); // must not panic
        }
    }

    // DD-037 Tier-1: the model handles C++ (mangling/vtables/templates), not just flat C.
    const SHAPES: &str = include_str!("../../../prototype/snapshots/shapes.x86-64.O0.json");

    #[test]
    fn ingests_cpp_with_demangled_names_vtables_and_templates() {
        let prog = snapshot_to_program(SHAPES).expect("parse C++ snapshot");
        let names: Vec<&str> = prog.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"main"));
        // Ghidra demangles: the template instantiation comes through readable.
        assert!(names.contains(&"max_of<int>"), "template instantiation should materialize");
        // Both virtual area() overrides (Circle::area, Square::area), demangled to "area".
        assert!(
            names.iter().filter(|n| **n == "area").count() >= 2,
            "both vtable area() overrides should materialize"
        );
        assert!(names.contains(&"Circle") && names.contains(&"Square"), "constructors present");
    }

    // DD-044: the snapshot carries the BSim feature vector as [[hash, f32_bits], …]; absent → empty.
    #[test]
    fn ingests_bsim_vector_and_degrades_when_absent() {
        let json = r#"{"program":"p","language":"x86:LE:64:default","functions":[
            {"entry":"0x1000","name":"factorial","size":40,"bb_count":3,
             "bsim_vector":[[3735928559,1065353216],[4660,1056964608]]}
        ]}"#;
        let prog = snapshot_to_program(json).expect("parse snapshot with bsim_vector");
        let f = prog.functions.iter().find(|f| f.name == "factorial").unwrap();
        // 0xDEADBEEF -> 1.0f32 bits, 0x1234 -> 0.5f32 bits — carried verbatim into the model.
        assert_eq!(
            f.bsim_vector,
            vec![(0xDEAD_BEEFu32, 1.0f32.to_bits()), (0x1234u32, 0.5f32.to_bits())]
        );
        // A snapshot without the field (the C++ SHAPES fixture isn't BSim-augmented) degrades
        // cleanly to empty — the cross-arch BSim pass simply won't fire for it.
        let bare = snapshot_to_program(SHAPES).unwrap();
        assert!(bare.functions.iter().all(|f| f.bsim_vector.is_empty()));
    }
}
