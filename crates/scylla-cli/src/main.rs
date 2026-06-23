//! `scylla` — the Scylla CLI. The engine port (DD-009/040) is THE materialization path: drive
//! GayHydra over gRPC and consume the `Materialize` stream straight into the canonical Cap'n
//! Proto artifact. No intermediate snapshot file, no `materialize.sh`, no second path.
//!
//!   scylla materialize <engine-endpoint> <binary> <out.scylla>
//!   scylla diff <a.scylla> <b.scylla>      # structural diff of two model artifacts (DD-017)
//!
//! The offline GayHydra-headless snapshot path still lives in `scylla-ingest`, for dev / corpus
//! work without a running engine-service — but the engine port is the one the product ships on.

use std::process::ExitCode;

use scylla_port::Session;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("materialize") if args.len() == 5 => materialize(&args[2], &args[3], &args[4]).await,
        Some("diff") if args.len() == 4 => diff(&args[2], &args[3]),
        _ => {
            eprintln!(
                "usage: {prog} materialize <engine-endpoint> <binary> <out.scylla>\n       \
                 {prog} diff <a.scylla> <b.scylla>\n\n  \
                 materialize — the engine port (DD-009/040): GayHydra over gRPC -> canonical artifact\n  \
                 diff        — structural diff of two artifacts (DD-017); exit 1 if they differ",
                prog = args.first().map(String::as_str).unwrap_or("scylla"),
            );
            ExitCode::from(2)
        }
    }
}

/// `scylla diff <a> <b>` — the offline `diff` verb (DD-017): load two model artifacts and report,
/// by display name, the functions matched / renamed / modified / added / removed across them. No
/// engine: structural identity pairs them, address-independent (a recompile re-pairs cleanly), and
/// a body change is re-identified by call-graph propagation rather than reported as remove+add.
/// `git diff --exit-code` semantics: 0 if structurally identical, 1 if they differ, 2 on trouble.
fn diff(a_path: &str, b_path: &str) -> ExitCode {
    let load = |p: &str| -> Result<Session, String> {
        let bytes = std::fs::read(p).map_err(|e| format!("reading {p}: {e}"))?;
        Session::from_artifact(&bytes).map_err(|e| format!("loading {p}: {e}"))
    };
    let (a, b) = match (load(a_path), load(b_path)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: {e}");
            return ExitCode::from(2); // git diff convention: 2 = trouble (distinct from 1 = differs)
        }
    };
    let d = a.diff(&b);
    let renamed: Vec<&(String, String)> = d.matched.iter().filter(|(x, y)| x != y).collect();
    let unchanged = d.matched.len() - renamed.len();

    println!("scylla diff: {a_path}  vs  {b_path}");
    println!(
        "  {unchanged} unchanged · {} renamed · {} modified · {} added · {} removed",
        renamed.len(),
        d.changed.len(),
        d.only_there.len(),
        d.only_here.len(),
    );
    let section = |title: &str, lines: &[String]| {
        if !lines.is_empty() {
            println!("\n{title}:");
            for l in lines {
                println!("  {l}");
            }
        }
    };
    section(
        "renamed",
        &renamed
            .iter()
            .map(|(x, y)| format!("{x} -> {y}"))
            .collect::<Vec<_>>(),
    );
    section(
        "modified",
        &d.changed
            .iter()
            .map(|(x, y)| {
                if x == y {
                    x.clone()
                } else {
                    format!("{x} -> {y}")
                }
            })
            .collect::<Vec<_>>(),
    );
    section(&format!("added (only in {b_path})"), &d.only_there);
    section(&format!("removed (only in {a_path})"), &d.only_here);

    let differs = !renamed.is_empty()
        || !d.changed.is_empty()
        || !d.only_here.is_empty()
        || !d.only_there.is_empty();
    if !differs {
        println!("\nno differences");
    }
    // git diff --exit-code semantics: 0 = identical, 1 = differs.
    if differs {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
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
