//! `scylla` — the Scylla CLI. The engine port (DD-009/040) is THE materialization path: drive
//! GayHydra over gRPC and consume the `Materialize` stream straight into the canonical Cap'n
//! Proto artifact. No intermediate snapshot file, no `materialize.sh`, no second path.
//!
//!   scylla materialize <engine-endpoint> <binary> <out.scylla>
//!
//! The offline GayHydra-headless snapshot path still lives in `scylla-ingest`, for dev / corpus
//! work without a running engine-service — but the engine port is the one the product ships on.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("materialize") if args.len() == 5 => materialize(&args[2], &args[3], &args[4]).await,
        _ => {
            eprintln!(
                "usage: {} materialize <engine-endpoint> <binary> <out.scylla>\n\n  \
                 the engine port (DD-009/040): GayHydra over gRPC -> canonical model artifact",
                args.first().map(String::as_str).unwrap_or("scylla"),
            );
            ExitCode::from(2)
        }
    }
}

/// Drive the engine port end to end: connect, stream the binary's functions back, and assemble
/// them into the model — the id mint and callee-address resolution happen core-side in
/// `scylla_engine::assemble`, so this is genuinely the core consuming the wire, not a shell script
/// shuttling JSON. Then write the Cap'n Proto artifact. A binary in, an artifact out, one gRPC
/// call. ALWAYS GayHydra.
async fn materialize(endpoint: &str, bin_path: &str, out: &str) -> ExitCode {
    let binary = match std::fs::read(bin_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: reading {bin_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let name = std::path::Path::new(bin_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("program");
    let prog = match scylla_engine::materialize(endpoint.to_string(), name, binary).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: engine materialize ({endpoint}): {e}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = scylla_schema::to_bytes(&prog);
    if let Err(e) = std::fs::write(out, &bytes) {
        eprintln!("error: writing {out}: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "Scylla: materialized {} functions from {name} -> {out} ({} bytes)",
        prog.functions.len(),
        bytes.len(),
    );
    ExitCode::SUCCESS
}
