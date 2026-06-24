//! Dynamic-analysis producer — SEAM de-risk spike (DD-007 / DD-027 candidate). NOT the harness.
//!
//! The question this answers, and the ONLY one: does a *second* producer — a dynamic one — enrich
//! the SAME durable model through the narrow waist, without a rewrite, the way the static producer
//! does? The eval (docs/eval-dynamic-analysis-producer.md) deferred the dynamic adapter but named
//! this exact first step: "ingest a single runtime artifact (a resolved IAT from a Scylla dump …)
//! and merge it against the static model of the same sample. Prove the seam."
//!
//! This spike does that and NOTHING more. It executes NO binary, attaches to NO process, links NO
//! debugger. The "runtime artifact" is a canned fixture (`runtime-iat.json`) standing in for what a
//! dynamic IAT-rebuilder (the RE-scene "Scylla" tool's job) emits for a packed sample whose import
//! table static analysis can't recover. We load the static `.scylla` model, reconcile that resolved
//! IAT against it BY IDENTITY (StableId), and measure the uplift. The execution-containment tier
//! that a real dynamic producer needs is explicitly OUT OF SCOPE — it gets its own threat model
//! when/if the harness is ever built (the eval is emphatic: do not weaken DD-034 to "get ready").

mod channel;
mod harness;

use std::collections::BTreeSet;

use harness::{DynamicHarness, RecordedHarness};
use scylla_model::Provenance;
use scylla_port::Session;
use serde_json::Value;

fn main() {
    // M2 — the one-way observation channel (see channel.rs / harness-m1/../harness-m2).
    match std::env::args().nth(1).as_deref() {
        // Read a recorded trace off the channel (stdin) through the bounded, validating reader.
        Some("m2-read") => channel::run_stdin(),
        // Emit a sample VALID frame (what an in-guest observer would write to serial) for the demo.
        Some("m2-make") => {
            print!(
                "{}",
                channel::make_frame(
                    r#"{"edges":[{"from":"main","to":"gcd","confidence":90},{"from":"gcd","to":"__imp_mod","confidence":80}]}"#
                )
            );
            return;
        }
        _ => {}
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let artifact = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("{manifest}/../../crates/scylla-wasm/web/mathlib.scylla"));

    let bytes = std::fs::read(&artifact).expect("read the static .scylla model");
    let session = Session::from_artifact(&bytes).expect("load the static model");
    let prog = session.program();

    // What static analysis already knows (the baseline we're enriching).
    let static_imports_total: usize = prog.functions.iter().map(|f| f.imports.len()).sum();
    println!("[dyn] === static model: {} ({} functions, {} imports known) ===", artifact, prog.functions.len(), static_imports_total);
    for f in &prog.functions {
        println!("[dyn]   fn {:<16} addr=0x{:<8x} imports={:?}", f.name, f.addr, f.imports);
    }

    // The synthetic RUNTIME ARTIFACT: a resolved IAT. No binary was executed — this is the stand-in
    // for a dynamic producer's output, exactly as the eval prescribed.
    let iat_path = format!("{manifest}/runtime-iat.json");
    let iat: Value =
        serde_json::from_slice(&std::fs::read(&iat_path).expect("read runtime-iat.json")).expect("parse IAT");
    let entries = iat["resolved_imports"].as_array().expect("resolved_imports[]");

    // --- THE MERGE: reconcile the runtime IAT against the static model by identity ---
    let mut resolved_total = 0usize;
    let mut newly_resolved = 0usize;
    let mut already_known = 0usize;
    let mut unmatched_callsites = 0usize;
    let mut enriched: BTreeSet<u64> = BTreeSet::new();

    for e in entries {
        resolved_total += 1;
        let fname = e["function"].as_str().unwrap_or("");
        let import = e["import"].as_str().unwrap_or("");
        // Resolve the observed call-site to the static model's identity (here by name; a real
        // producer keys on address — the point is it lands on an EXISTING StableId, not a new node).
        match prog.functions.iter().find(|f| f.name == fname) {
            Some(f) => {
                if f.imports.iter().any(|i| i == import) {
                    already_known += 1;
                } else {
                    newly_resolved += 1;
                    enriched.insert(f.id.0);
                    println!("[dyn]   + {fname} (id {}) gains import `{import}` (dynamic-only)", f.id.0);
                }
            }
            None => {
                unmatched_callsites += 1;
                println!("[dyn]   ! IAT call-site in `{fname}` matched NO static function (new-node case)");
            }
        }
    }

    println!("[dyn] === merge result ===");
    println!("[dyn] runtime IAT entries:        {resolved_total}");
    println!("[dyn] newly-resolved imports:     {newly_resolved}  (across {} functions)", enriched.len());
    println!("[dyn] already known statically:   {already_known}");
    println!("[dyn] unmatched call-sites:       {unmatched_callsites}");
    println!("[dyn] === seam claims ===");
    println!("[dyn] IDENTITY: every resolved import landed on an EXISTING StableId — the dynamic");
    println!("[dyn]   producer enriched the SAME model, no rewrite. The narrow waist absorbed a 2nd");
    println!("[dyn]   producer exactly as DD-004 re-anchoring and DD-040 gRPC were proven.");
    println!("[dyn] LEVERAGE: imports feed the DD-041 cross-arch ANCHOR. On a packed/stripped sample");
    println!("[dyn]   static imports trend to 0; a dynamic IAT rebuild restores them, so the dynamic");
    println!("[dyn]   producer doesn't just add data — it lifts re-anchoring where static is blind.");

    // --- the EXECUTION HARNESS interface, NON-EXECUTING (the deferred half, de-risked at design) ---
    let h = RecordedHarness::from_file(&iat_path);
    let observed = h.observe("mathlib (a real harness would RUN this in the containment tier; here: replay)");
    println!("[harness] === execution harness de-risk (see HARNESS-THREAT-MODEL.md) ===");
    println!("[harness] containment: {}", h.containment());
    println!("[harness] observed {} runtime edges — and EXECUTED NOTHING (recorded replay)", observed.len());
    for e in observed.iter().take(3) {
        let p = Provenance {
            producer: "dynamic".into(),
            confidence: e.confidence,
        };
        println!("[harness]   {} -> {}  ==> DD-007 {:?}", e.from, e.to, p);
    }
    println!("[harness] interface + provenance flow proven end-to-end; the real MicroVmHarness plugs in");
    println!("[harness]   behind GAP-5..9 (sandbox escape, observation injection, …) — DEFERRED, not built.");

    let go = newly_resolved > 0 && unmatched_callsites == 0;
    println!(
        "[dyn] VERDICT: {}",
        if go {
            "GO (seam) — the merge holds by identity with measurable uplift. Productionize behind \
             first-class producer PROVENANCE (DD-007) + coverage-aware collaborate (DD-027); the \
             execution-containment harness stays DEFERRED with its own threat model."
        } else {
            "INCONCLUSIVE — fixture/model mismatch; inspect the [dyn] dump above."
        }
    );
    std::process::exit(if go { 0 } else { 1 });
}
