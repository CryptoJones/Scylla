//! `scylla` — the Scylla CLI. The engine port (DD-009/040) is THE materialization path: drive
//! GayHydra over gRPC and consume the `Materialize` stream straight into the canonical Cap'n
//! Proto artifact. No intermediate snapshot file, no `materialize.sh`, no second path.
//!
//!   scylla materialize <engine-endpoint> <binary> <out.scylla>
//!   scylla diff <a.scylla> <b.scylla>      # structural diff of two model artifacts (DD-017)
//!   scylla info <artifact.scylla>          # name / language / function count
//!   scylla functions <artifact.scylla> [intent|domain|detail]   # list functions at a zoom
//!   scylla view <artifact.scylla> <id> [zoom]   # one function's detail + call graph
//!   scylla callers <artifact.scylla> <id>       # functions that call <id>
//!
//! The offline GayHydra-headless snapshot path still lives in `scylla-ingest`, for dev / corpus
//! work without a running engine-service — but the engine port is the one the product ships on.

use std::process::ExitCode;

use scylla_model::StableId;
use scylla_port::{Session, Zoom};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("materialize") if args.len() == 5 => materialize(&args[2], &args[3], &args[4]).await,
        Some("diff") if args.len() == 4 => diff(&args[2], &args[3]),
        Some("info") if args.len() == 3 => info(&args[2]),
        Some("functions") if args.len() == 3 || args.len() == 4 => {
            functions(&args[2], args.get(3).map(String::as_str))
        }
        Some("view") if args.len() == 4 || args.len() == 5 => {
            view(&args[2], &args[3], args.get(4).map(String::as_str))
        }
        Some("callers") if args.len() == 4 => callers(&args[2], &args[3]),
        _ => {
            eprintln!(
                "usage: {prog} materialize <engine-endpoint> <binary> <out.scylla>\n       \
                 {prog} diff <a.scylla> <b.scylla>\n       \
                 {prog} info <artifact.scylla>\n       \
                 {prog} functions <artifact.scylla> [intent|domain|detail]\n       \
                 {prog} view <artifact.scylla> <id> [intent|domain|detail]\n       \
                 {prog} callers <artifact.scylla> <id>\n\n  \
                 materialize — the engine port (DD-009/040): GayHydra over gRPC -> canonical artifact\n  \
                 diff        — structural diff of two artifacts (DD-017); exit 1 if they differ\n  \
                 info        — artifact metadata (name / language / function count)\n  \
                 functions   — list functions at a zoom altitude (default domain)\n  \
                 view        — one function by stable id at a zoom altitude\n  \
                 callers     — the functions that call a given function (call-graph navigation)",
                prog = args.first().map(String::as_str).unwrap_or("scylla"),
            );
            ExitCode::from(2)
        }
    }
}

/// Load a `.scylla` artifact into a read-only session, or print the error + exit 2 (trouble).
fn load_session(path: &str) -> Result<Session, ExitCode> {
    let bytes = std::fs::read(path).map_err(|e| {
        eprintln!("error: reading {path}: {e}");
        ExitCode::from(2)
    })?;
    Session::from_artifact(&bytes).map_err(|e| {
        eprintln!("error: loading {path}: {e}");
        ExitCode::from(2)
    })
}

/// `scylla info <artifact>` — the artifact's name, language, and function count (offline, no engine).
fn info(path: &str) -> ExitCode {
    let session = match load_session(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let p = session.program();
    println!("name:      {}", p.name);
    println!("language:  {}", p.language);
    println!("functions: {}", p.functions.len());
    ExitCode::SUCCESS
}

/// Parse a zoom-altitude argument (DD-020), defaulting to domain; `Err` (exit 2) on a bad value.
fn parse_zoom(arg: Option<&str>) -> Result<Zoom, ExitCode> {
    match arg {
        None | Some("domain") => Ok(Zoom::Domain),
        Some("intent") => Ok(Zoom::Intent),
        Some("detail") => Ok(Zoom::Detail),
        Some(other) => {
            eprintln!("error: unknown zoom {other:?} (want intent|domain|detail)");
            Err(ExitCode::from(2))
        }
    }
}

/// Parse a stable id, or print the error + exit 2.
fn parse_id(s: &str) -> Result<StableId, ExitCode> {
    s.parse::<u64>().map(StableId).map_err(|_| {
        eprintln!("error: id must be an integer, got {s:?}");
        ExitCode::from(2)
    })
}

/// `scylla functions <artifact> [zoom]` — list every function at a zoom altitude (DD-020), one per
/// line as `<id>\t<name>\t<summary>`, sorted by name for a stable, greppable, diff-friendly listing.
fn functions(path: &str, zoom_arg: Option<&str>) -> ExitCode {
    let zoom = match parse_zoom(zoom_arg) {
        Ok(z) => z,
        Err(code) => return code,
    };
    let session = match load_session(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut fns = session.functions(zoom);
    fns.sort_by(|a, b| a.name.cmp(&b.name));
    for f in &fns {
        println!("{}\t{}\t{}", f.id.0, f.name, f.summary);
    }
    ExitCode::SUCCESS
}

/// `scylla view <artifact> <id> [zoom]` — one function by stable id at a zoom altitude (DD-020).
fn view(path: &str, id_arg: &str, zoom_arg: Option<&str>) -> ExitCode {
    let zoom = match parse_zoom(zoom_arg) {
        Ok(z) => z,
        Err(code) => return code,
    };
    let id = match parse_id(id_arg) {
        Ok(i) => i,
        Err(code) => return code,
    };
    let session = match load_session(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let v = match session.view(id, zoom) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let list = |xs: &[String]| {
        if xs.is_empty() {
            "(none)".to_string()
        } else {
            xs.join(", ")
        }
    };
    println!("name:    {}", v.name);
    println!("summary: {}", v.summary);
    if let Some(a) = v.addr {
        println!("address: 0x{a:x}");
    }
    if let Some(b) = v.bb_count {
        println!("blocks:  {b}");
    }
    if let Some(s) = v.size {
        println!("size:    {s} bytes");
    }
    if let Some(c) = &v.callees {
        println!("calls:   {}", list(c));
    }
    if let Some(c) = &v.callers {
        println!("callers: {}", list(c));
    }
    ExitCode::SUCCESS
}

/// `scylla callers <artifact> <id>` — the functions that call `id` (call-graph navigation), one per
/// line as `<id>\t<name>`, sorted by name. An unknown id is trouble (exit 2), distinct from a known
/// id with no callers (exit 0, empty output).
fn callers(path: &str, id_arg: &str) -> ExitCode {
    let id = match parse_id(id_arg) {
        Ok(i) => i,
        Err(code) => return code,
    };
    let session = match load_session(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let prog = session.program();
    if !prog.functions.iter().any(|f| f.id == id) {
        eprintln!("error: no function with id {}", id.0);
        return ExitCode::from(2);
    }
    let mut callers: Vec<(u64, String)> = session
        .callers(id)
        .into_iter()
        .map(|c| (c.0, prog.display_name(c).unwrap_or_default()))
        .collect();
    callers.sort_by(|a, b| a.1.cmp(&b.1));
    for (cid, cname) in &callers {
        println!("{cid}\t{cname}");
    }
    ExitCode::SUCCESS
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
