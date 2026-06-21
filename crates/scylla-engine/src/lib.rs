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

use scylla_model::{Function, StableId};

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
    }
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
}
