//! First materialization path (Sprint 4): a GayHydra headless **snapshot** (the JSON the
//! prototype harness already emits) → the native [`scylla_model::Program`].
//!
//! This is the producer side of the engine-port narrow waist (DD-009) in its simplest form:
//! the heavy JVM engine analyzes a binary out-of-process and hands us a coarse snapshot; we
//! mint stable ids (DD-004), resolve the call graph onto them, and the result serializes to
//! the canonical Cap'n Proto artifact (DD-002/026) via `scylla-schema`.

use std::collections::HashMap;

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

fn parse_addr(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(0)
}

/// Build a native model `Program` from a snapshot JSON string.
pub fn snapshot_to_program(json: &str) -> serde_json::Result<Program> {
    let snap: Snapshot = serde_json::from_str(json)?;
    let mut minter = IdMinter::new();

    // Pass 1: mint one stable id per function, keyed by its (current) entry address.
    // The address is just the key here — identity is the minted id, not the address (DD-004).
    let mut id_of: HashMap<u64, StableId> = HashMap::new();
    for f in &snap.functions {
        id_of.insert(parse_addr(&f.entry), minter.mint());
    }

    // Pass 2: build functions, resolving call edges to stable ids.
    let mut functions = Vec::with_capacity(snap.functions.len());
    for f in &snap.functions {
        let addr = parse_addr(&f.entry);
        let callees = f
            .callees
            .iter()
            .filter_map(|c| id_of.get(&parse_addr(c)).copied())
            .collect();
        let histogram = scylla_model::mnemonic_histogram(&f.mnemonics);
        functions.push(Function {
            id: id_of[&addr],
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
