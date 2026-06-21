//! The **engine port** (DD-009 / DD-040): the Rust core's gRPC client to the sandboxed JVM
//! engine-as-service, plus the mapping from wire chunks to the native model.
//!
//! This is the *producer-side* waist. It speaks protobuf (tonic); the model/client side stays
//! Cap'n Proto (DD-002). The JVM service (a standalone Ghidra-headless + grpc-java process) is
//! built next, after the coexistence spike (DD-040) — this crate is the contract + client half,
//! buildable and testable without a live engine.

pub mod pb {
    tonic::include_proto!("scylla.engine.v1");
}

use std::collections::HashMap;

use scylla_model::{Function, IdMinter, Program, StableId};

/// Map a streamed wire chunk to a model function. The callee *addresses* are carried through
/// untouched; resolving them to stable ids happens core-side in a second pass (as ingest does),
/// because the id mint is the core's job, not the wire's.
pub fn chunk_to_function(chunk: &pb::FunctionChunk, id: StableId) -> Function {
    Function {
        id,
        addr: chunk.entry,
        name: chunk.name.clone(),
        size: chunk.size,
        bb_count: chunk.bb_count,
        callees: Vec::new(),
        // The SAME fingerprint the snapshot path computes (scylla_model::mnemonic_fingerprint),
        // from the mnemonics the engine now streams — so a gRPC-materialized artifact and a
        // snapshot-materialized one share fingerprints and re-anchor against each other (DD-038).
        fingerprint: scylla_model::mnemonic_fingerprint(&chunk.mnemonics),
    }
}

/// Assemble streamed wire chunks into a native model `Program`: mint a stable id per function
/// (keyed by entry address), then resolve callee *addresses* to those stable ids in a second
/// pass (dangling callees dropped). Pure — the gRPC-free core of materialization, testable
/// without a live engine. (Program `language` isn't on the wire yet — see BACKLOG.)
pub fn assemble(name: &str, chunks: &[pb::FunctionChunk]) -> Program {
    let mut minter = IdMinter::new();
    let mut id_of: HashMap<u64, StableId> = HashMap::new();
    for c in chunks {
        id_of.insert(c.entry, minter.mint());
    }
    let functions = chunks
        .iter()
        .map(|c| {
            let mut f = chunk_to_function(c, id_of[&c.entry]);
            f.callees = c.callees.iter().filter_map(|a| id_of.get(a).copied()).collect();
            f
        })
        .collect();
    Program {
        name: name.to_string(),
        language: String::new(),
        functions,
        facts: Vec::new(),
    }
}

/// GAP-3 (DD-036 spirit): the engine is UNTRUSTED output. A compromised or buggy engine must not
/// OOM the trusted core by streaming unbounded functions or instructions, so the core bounds what
/// it will accept from the `Materialize` stream and fails closed past it. (Each individual message
/// is already bounded by tonic's max-decode size; these cap the *cumulative* stream.)
pub const MAX_FUNCTIONS: usize = 1_000_000;
/// Cumulative instruction (mnemonic) ceiling across the whole stream.
pub const MAX_TOTAL_MNEMONICS: usize = 100_000_000;

/// Refuse an over-large engine stream. `Err(reason)` when a cap is exceeded; `Ok` at/under it.
fn check_stream_caps(n_functions: usize, total_mnemonics: usize) -> Result<(), String> {
    if n_functions > MAX_FUNCTIONS {
        return Err(format!(
            "engine stream exceeded {MAX_FUNCTIONS} functions — refusing (untrusted engine output)"
        ));
    }
    if total_mnemonics > MAX_TOTAL_MNEMONICS {
        return Err(format!(
            "engine stream exceeded {MAX_TOTAL_MNEMONICS} instructions — refusing (untrusted engine output)"
        ));
    }
    Ok(())
}

/// The engine-port path: connect to the engine-service, materialize a binary over gRPC, and
/// assemble the native model. This is the Rust core driving GayHydra over the DD-040 contract.
pub async fn materialize(
    endpoint: String,
    name: &str,
    binary: Vec<u8>,
) -> Result<Program, Box<dyn std::error::Error>> {
    let mut client = pb::engine_client::EngineClient::connect(endpoint).await?;
    let mut stream = client
        .materialize(pb::MaterializeRequest { binary, arch_hint: String::new() })
        .await?
        .into_inner();
    let mut chunks = Vec::new();
    let mut total_mnemonics = 0usize;
    while let Some(c) = stream.message().await? {
        // Bound the untrusted stream BEFORE retaining the chunk — fail closed, never OOM.
        total_mnemonics += c.mnemonics.len();
        check_stream_caps(chunks.len() + 1, total_mnemonics)?;
        chunks.push(c);
    }
    Ok(assemble(name, &chunks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_chunk_maps_to_a_model_function() {
        let chunk = pb::FunctionChunk {
            entry: 0x401156,
            name: "gcd".into(),
            size: 64,
            bb_count: 4,
            callees: vec![],
            mnemonics: vec!["PUSH".into(), "MOV".into(), "DIV".into(), "RET".into()],
        };
        let f = chunk_to_function(&chunk, StableId(1));
        assert_eq!(f.id, StableId(1));
        assert_eq!(f.addr, 0x401156);
        assert_eq!(f.name, "gcd");
        assert_eq!(f.bb_count, 4);
        // The wire mnemonics fold into the SAME fingerprint the snapshot path computes.
        assert_eq!(f.fingerprint, scylla_model::mnemonic_fingerprint(&chunk.mnemonics));
        assert_ne!(f.fingerprint, 0, "a chunk with mnemonics gets a real fingerprint");
    }

    #[test]
    fn stream_caps_refuse_an_oversized_engine_stream() {
        // GAP-3: a compromised engine can't OOM the core. At the cap is fine; over it is refused.
        assert!(check_stream_caps(10, 1_000).is_ok());
        assert!(check_stream_caps(MAX_FUNCTIONS, MAX_TOTAL_MNEMONICS).is_ok());
        assert!(check_stream_caps(MAX_FUNCTIONS + 1, 0).is_err(), "too many functions refused");
        assert!(check_stream_caps(1, MAX_TOTAL_MNEMONICS + 1).is_err(), "too many instructions refused");
    }

    #[test]
    fn assemble_mints_ids_and_resolves_callees() {
        let chunks = vec![
            pb::FunctionChunk { entry: 0x1000, name: "gcd".into(), size: 64, bb_count: 4, callees: vec![], mnemonics: vec![] },
            pb::FunctionChunk { entry: 0x2000, name: "main".into(), size: 180, bb_count: 4, callees: vec![0x1000, 0x9999], mnemonics: vec![] },
        ];
        let p = assemble("prog", &chunks);
        assert_eq!(p.name, "prog");
        let gcd = p.functions.iter().find(|f| f.name == "gcd").unwrap();
        let main = p.functions.iter().find(|f| f.name == "main").unwrap();
        assert!(main.callees.contains(&gcd.id), "main -> gcd resolved to a stable id");
        assert_eq!(main.callees.len(), 1, "dangling callee 0x9999 is dropped");
        assert_ne!(gcd.id, main.id);
    }
}
