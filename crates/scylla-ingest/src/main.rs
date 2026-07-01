//! `scylla-ingest <snapshot.json> <out.scylla>` — materialize a GayHydra headless snapshot
//! into a canonical Cap'n Proto model artifact.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        let prog = args.first().map(String::as_str).unwrap_or("scylla-ingest");
        eprintln!("usage: {prog} <snapshot.json> <out.scylla>");
        return ExitCode::from(2);
    }
    let json = match std::fs::read_to_string(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading {}: {e}", args[1]);
            return ExitCode::FAILURE;
        }
    };
    let prog = match scylla_ingest::snapshot_to_program(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: parsing snapshot: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = scylla_schema::to_bytes(&prog);
    if let Err(e) = std::fs::write(&args[2], &bytes) {
        eprintln!("error: writing {}: {e}", args[2]);
        return ExitCode::FAILURE;
    }
    eprintln!(
        "Scylla: materialized {} functions -> {} ({} bytes)",
        prog.functions.len(),
        args[2],
        bytes.len()
    );
    ExitCode::SUCCESS
}
