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
        // The engine.proto FunctionChunk doesn't carry mnemonics yet, so the gRPC path produces
        // no fingerprint (0 = no data, degrades gracefully to the coarse signature). Carrying the
        // mnemonic histogram over the wire is the tracked follow-up (see BACKLOG.md).
        fingerprint: 0,
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
    while let Some(c) = stream.message().await? {
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
        };
        let f = chunk_to_function(&chunk, StableId(1));
        assert_eq!(f.id, StableId(1));
        assert_eq!(f.addr, 0x401156);
        assert_eq!(f.name, "gcd");
        assert_eq!(f.bb_count, 4);
    }

    #[test]
    fn assemble_mints_ids_and_resolves_callees() {
        let chunks = vec![
            pb::FunctionChunk { entry: 0x1000, name: "gcd".into(), size: 64, bb_count: 4, callees: vec![] },
            pb::FunctionChunk { entry: 0x2000, name: "main".into(), size: 180, bb_count: 4, callees: vec![0x1000, 0x9999] },
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
