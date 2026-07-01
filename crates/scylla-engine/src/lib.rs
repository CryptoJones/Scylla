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

pub mod job;

use std::collections::{HashMap, HashSet};

use scylla_model::{Function, IdMinter, Program, StableId};

/// Map a streamed wire chunk to a model function. The callee *addresses* are carried through
/// untouched; resolving them to stable ids happens core-side in a second pass (as ingest does),
/// because the id mint is the core's job, not the wire's.
pub fn chunk_to_function(chunk: &pb::FunctionChunk, id: StableId) -> Function {
    // The histogram from the mnemonics the engine streams — and its hash. The SAME computation the
    // snapshot path uses, so a gRPC-materialized artifact and a snapshot one share both and
    // re-anchor against each other (DD-038, exact + fuzzy).
    let histogram = scylla_model::mnemonic_histogram(&chunk.mnemonics);
    Function {
        id,
        addr: chunk.entry,
        name: chunk.name.clone(),
        size: chunk.size,
        bb_count: chunk.bb_count,
        callees: Vec::new(),
        fingerprint: scylla_model::histogram_fingerprint(&histogram),
        // Ordered trigrams from the streamed in-order mnemonics — same computation as the snapshot
        // path, before the histogram drops the order; so live + offline artifacts carry the signal.
        trigrams: scylla_model::mnemonic_trigrams(&chunk.mnemonics),
        mnemonics: histogram,
        // Arch-independent features (DD-041) ride the wire raw — the engine already emits them; the
        // core just carries them, same as the snapshot path, so live + offline artifacts re-anchor.
        string_refs: chunk.string_refs.clone(),
        imports: chunk.imports.clone(),
        callee_names: chunk.callee_names.clone(),
        // BSim LSH feature vector (DD-044): (hash, f32-weight-bits) pairs the engine streams.
        bsim_vector: chunk
            .bsim_vector
            .iter()
            .map(|bf| (bf.hash, bf.weight))
            .collect(),
        // The static gRPC producer records no per-edge provenance (DD-007); a dynamic producer would.
        edge_provenance: Vec::new(),
    }
}

/// Assemble streamed wire chunks into a native model `Program`: mint a stable id per function
/// (keyed by entry address), then resolve callee *addresses* to those stable ids in a second
/// pass (dangling callees dropped). Pure — the gRPC-free core of materialization, testable
/// without a live engine. `name`/`language` come from the stream's `ProgramInfo` header.
pub fn assemble(name: &str, language: &str, chunks: &[pb::FunctionChunk]) -> Program {
    let mut minter = IdMinter::new();
    // Mint one stable id per chunk by INDEX. The engine is UNTRUSTED (GAP-3), so two chunks sharing
    // an entry address must NOT collapse onto one stable id (identity is the minted id, DD-004). A
    // separate address->id map drives callee resolution and DROPS ambiguous (duplicated) addresses,
    // so a callee to such an address resolves to nothing rather than to the wrong function.
    let ids: Vec<StableId> = chunks.iter().map(|_| minter.mint()).collect();
    let mut addr_to_id: HashMap<u64, StableId> = HashMap::new();
    let mut ambiguous: HashSet<u64> = HashSet::new();
    for (c, &id) in chunks.iter().zip(&ids) {
        if addr_to_id.insert(c.entry, id).is_some() {
            ambiguous.insert(c.entry);
        }
    }
    for a in &ambiguous {
        addr_to_id.remove(a);
    }
    let functions = chunks
        .iter()
        .zip(&ids)
        .map(|(c, &id)| {
            let mut f = chunk_to_function(c, id);
            f.callees = c
                .callees
                .iter()
                .filter_map(|a| addr_to_id.get(a).copied())
                .collect();
            f
        })
        .collect();
    Program {
        name: name.to_string(),
        language: language.to_string(),
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
/// Cumulative BYTE ceiling across ALL retained fields of the stream. The count caps above miss a
/// malicious engine that streams unbounded `string_refs`/`imports`/`callee_names`/`bsim_vector` with
/// zero mnemonics (~4 TB without tripping either count cap); a byte budget closes that. 512 MiB
/// matches the artifact loader's traversal ceiling.
pub const MAX_TOTAL_BYTES: usize = 512 * 1024 * 1024;

/// Approximate the retained byte size of a streamed chunk (all fields that survive into the model).
fn chunk_bytes(c: &pb::FunctionChunk) -> usize {
    c.name.len()
        + c.mnemonics.iter().map(String::len).sum::<usize>()
        + c.string_refs.iter().map(String::len).sum::<usize>()
        + c.imports.iter().map(String::len).sum::<usize>()
        + c.callee_names.iter().map(String::len).sum::<usize>()
        + c.bsim_vector.len() * 8
        + c.callees.len() * 8
}

/// Refuse an over-large engine stream. `Err(reason)` when a cap is exceeded; `Ok` at/under it.
fn check_stream_caps(
    n_functions: usize,
    total_mnemonics: usize,
    total_bytes: usize,
) -> Result<(), String> {
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
    if total_bytes > MAX_TOTAL_BYTES {
        return Err(format!(
            "engine stream exceeded {MAX_TOTAL_BYTES} bytes — refusing (untrusted engine output)"
        ));
    }
    Ok(())
}

/// Connect to the engine-service. A `unix:/path/to.sock` endpoint dials a **Unix-domain socket**
/// (the no-egress sandbox — DD-034 GAP-1, where the container runs with `--network none` and a
/// hostile binary has no network to phone home over); anything else is a normal TCP/HTTP endpoint.
pub async fn connect_engine(
    endpoint: String,
) -> Result<pb::engine_client::EngineClient<tonic::transport::Channel>, Box<dyn std::error::Error>>
{
    if let Some(path) = endpoint.strip_prefix("unix:") {
        let path = path.to_string();
        // The URI is a placeholder — the connector ignores it and dials the socket path.
        let channel = tonic::transport::Endpoint::try_from("http://[::1]:50051")?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await?;
        Ok(pb::engine_client::EngineClient::new(channel))
    } else {
        Ok(pb::engine_client::EngineClient::connect(endpoint).await?)
    }
}

/// The engine-port path: connect to the engine-service, materialize a binary over gRPC, and
/// assemble the native model. This is the Rust core driving GayHydra over the DD-040 contract.
/// The stream is a `ProgramInfo` header (name/language) then one `FunctionChunk` per function;
/// `name` is the fallback program name if the engine sends none.
pub async fn materialize(
    endpoint: String,
    name: &str,
    binary: Vec<u8>,
) -> Result<Program, Box<dyn std::error::Error>> {
    use pb::materialize_event::Event;
    let mut client = connect_engine(endpoint).await?;
    let mut stream = client
        .materialize(pb::MaterializeRequest {
            binary,
            arch_hint: String::new(),
        })
        .await?
        .into_inner();
    let mut chunks = Vec::new();
    let mut total_mnemonics = 0usize;
    let mut total_bytes = 0usize;
    let mut prog_name = name.to_string();
    let mut language = String::new();
    while let Some(ev) = stream.message().await? {
        match ev.event {
            Some(Event::Info(info)) => {
                if !info.name.is_empty() {
                    prog_name = info.name;
                }
                language = info.language;
            }
            Some(Event::Function(c)) => {
                // Bound the untrusted stream BEFORE retaining the chunk — fail closed, never OOM.
                total_mnemonics += c.mnemonics.len();
                total_bytes += chunk_bytes(&c);
                check_stream_caps(chunks.len() + 1, total_mnemonics, total_bytes)?;
                chunks.push(c);
            }
            None => {} // an empty event — ignore
        }
    }
    Ok(assemble(&prog_name, &language, &chunks))
}

/// The engine-port `decompile` verb (DD-017): ask the engine for the decompiled C of the function
/// at `entry`. Producer-side and on-demand — the client port surfaces it but the call lives up here
/// on the async side, so the sync model-consuming port stays pure (DD-009). The returned C is
/// untrusted engine output (DD-035); a head treats it as data, never instruction.
pub async fn decompile(endpoint: String, entry: u64) -> Result<String, Box<dyn std::error::Error>> {
    let mut client = connect_engine(endpoint).await?;
    let reply = client
        .decompile(pb::DecompileRequest { entry })
        .await?
        .into_inner();
    Ok(reply.c)
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
            string_refs: vec![],
            imports: vec![],
            callee_names: vec![],
            bsim_vector: vec![],
        };
        let f = chunk_to_function(&chunk, StableId(1));
        assert_eq!(f.id, StableId(1));
        assert_eq!(f.addr, 0x401156);
        assert_eq!(f.name, "gcd");
        assert_eq!(f.bb_count, 4);
        // The wire mnemonics fold into the SAME fingerprint + histogram the snapshot path computes.
        assert_eq!(
            f.fingerprint,
            scylla_model::mnemonic_fingerprint(&chunk.mnemonics)
        );
        assert_eq!(
            f.mnemonics,
            scylla_model::mnemonic_histogram(&chunk.mnemonics)
        );
        assert_ne!(
            f.fingerprint, 0,
            "a chunk with mnemonics gets a real fingerprint"
        );
    }

    #[test]
    fn stream_caps_refuse_an_oversized_engine_stream() {
        // GAP-3: a compromised engine can't OOM the core. At the cap is fine; over it is refused.
        assert!(check_stream_caps(10, 1_000, 1_000).is_ok());
        assert!(check_stream_caps(MAX_FUNCTIONS, MAX_TOTAL_MNEMONICS, MAX_TOTAL_BYTES).is_ok());
        assert!(
            check_stream_caps(MAX_FUNCTIONS + 1, 0, 0).is_err(),
            "too many functions refused"
        );
        assert!(
            check_stream_caps(1, MAX_TOTAL_MNEMONICS + 1, 0).is_err(),
            "too many instructions refused"
        );
        assert!(
            check_stream_caps(1, 0, MAX_TOTAL_BYTES + 1).is_err(),
            "a byte flood with zero mnemonics is refused"
        );
    }

    #[test]
    fn assemble_gives_distinct_ids_on_duplicate_entry_addresses() {
        // A buggy/compromised engine (GAP-3) could stream two functions at the same entry address.
        // They must get DISTINCT stable ids (DD-004), and a call to that now-ambiguous address must
        // resolve to nothing, never the wrong function.
        let mk = |entry: u64, name: &str, callees: Vec<u64>| pb::FunctionChunk {
            entry,
            name: name.into(),
            size: 1,
            bb_count: 1,
            callees,
            mnemonics: vec![],
            string_refs: vec![],
            imports: vec![],
            callee_names: vec![],
            bsim_vector: vec![],
        };
        let chunks = vec![
            mk(0x1000, "a", vec![]),
            mk(0x1000, "b", vec![]),
            mk(0x2000, "caller", vec![0x1000]),
        ];
        let prog = assemble("p", "l", &chunks);
        let id = |n: &str| prog.functions.iter().find(|f| f.name == n).unwrap().id;
        assert_ne!(id("a"), id("b"), "duplicate entry addresses must not share a stable id");
        let caller = prog.functions.iter().find(|f| f.name == "caller").unwrap();
        assert!(caller.callees.is_empty(), "a call to the ambiguous address resolves to nothing");
    }

    #[test]
    fn assemble_mints_ids_and_resolves_callees() {
        let chunks = vec![
            pb::FunctionChunk {
                entry: 0x1000,
                name: "gcd".into(),
                size: 64,
                bb_count: 4,
                callees: vec![],
                mnemonics: vec![],
                string_refs: vec![],
                imports: vec![],
                callee_names: vec![],
                bsim_vector: vec![],
            },
            pb::FunctionChunk {
                entry: 0x2000,
                name: "main".into(),
                size: 180,
                bb_count: 4,
                callees: vec![0x1000, 0x9999],
                mnemonics: vec![],
                string_refs: vec!["result=%d\n".into()],
                imports: vec!["printf".into()],
                callee_names: vec![],
                bsim_vector: vec![],
            },
        ];
        let p = assemble("prog", "x86:LE:64:default", &chunks);
        assert_eq!(p.name, "prog");
        assert_eq!(
            p.language, "x86:LE:64:default",
            "language from the ProgramInfo header survives"
        );
        let gcd = p.functions.iter().find(|f| f.name == "gcd").unwrap();
        let main = p.functions.iter().find(|f| f.name == "main").unwrap();
        assert!(
            main.callees.contains(&gcd.id),
            "main -> gcd resolved to a stable id"
        );
        assert_eq!(main.callees.len(), 1, "dangling callee 0x9999 is dropped");
        // Arch-independent features (DD-041) ride the wire into the model unchanged.
        assert_eq!(main.string_refs, vec!["result=%d\n".to_string()]);
        assert_eq!(main.imports, vec!["printf".to_string()]);
        assert_ne!(gcd.id, main.id);
    }

    /// DD-017 Sprint-6 DoD: a NON-MCP client drives a full session over the engine→port handoff —
    /// materialize → open the pure client port → navigate → annotate → persist → reload. Here
    /// materialize is fixture chunks via `assemble`; live it's `materialize(endpoint, …).await`,
    /// the same one-liner (`Session::open(...)`). The engine head-layer is exactly this wiring; the
    /// port stays a pure model consumer (DD-009) and never depends on the engine.
    #[test]
    fn non_mcp_client_drives_a_full_session_over_the_engine_port() {
        use scylla_port::{Session, Zoom};
        let chunks = vec![
            pb::FunctionChunk {
                entry: 0x1000,
                name: "gcd".into(),
                size: 64,
                bb_count: 4,
                callees: vec![],
                mnemonics: vec![],
                string_refs: vec![],
                imports: vec![],
                callee_names: vec![],
                bsim_vector: vec![],
            },
            pb::FunctionChunk {
                entry: 0x2000,
                name: "main".into(),
                size: 180,
                bb_count: 4,
                callees: vec![0x1000],
                mnemonics: vec![],
                string_refs: vec!["r=%d\n".into()],
                imports: vec!["printf".into()],
                callee_names: vec![],
                bsim_vector: vec![],
            },
        ];
        // materialize (engine-side) -> open the client port: the head-layer one-liner.
        let mut session = Session::open(assemble("prog", "x86:LE:64:default", &chunks));
        let id = |n: &str| {
            session
                .program()
                .functions
                .iter()
                .find(|f| f.name == n)
                .unwrap()
                .id
        };
        let (gcd, main) = (id("gcd"), id("main"));
        // navigate: main calls gcd.
        assert!(session
            .view(main, Zoom::Domain)
            .unwrap()
            .callees
            .unwrap()
            .contains(&"gcd".to_string()));
        // annotate, then persist + reload (the fact survives on the stable id).
        session.rename(gcd, "euclid_gcd").unwrap();
        let reloaded = Session::from_artifact(&session.to_artifact()).unwrap();
        assert_eq!(reloaded.view(gcd, Zoom::Domain).unwrap().name, "euclid_gcd");
    }
}
