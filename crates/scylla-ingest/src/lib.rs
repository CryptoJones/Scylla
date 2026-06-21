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
        functions.push(Function {
            id: id_of[&addr],
            addr,
            name: f.name.clone(),
            size: f.size,
            bb_count: f.bb_count,
            callees,
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
}
