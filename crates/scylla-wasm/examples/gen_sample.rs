//! Generate the WASM demo's sample artifact: the mathlib snapshot → a `Program` → a `.scylla`
//! model-artifact the browser loads. Run from anywhere:
//!
//!   cargo run -p scylla-wasm --example gen_sample
//!
//! Throwaway helper; the artifact it writes (`web/mathlib.scylla`) is what the demo ships.

use std::fs;
use std::path::Path;

const SNAPSHOT: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

fn write(name: &str, program: scylla_model::Program) {
    let bytes = scylla_port::Session::open(program).to_artifact();
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("web").join(name);
    fs::write(&out, &bytes).expect("write artifact");
    println!("wrote {} ({} bytes)", out.display(), bytes.len());
}

fn main() {
    // The demo artifact.
    write(
        "mathlib.scylla",
        scylla_ingest::snapshot_to_program(SNAPSHOT).unwrap(),
    );
    // A "re-analysis": the same binary materialized again — same structure, FRESH stable ids — so
    // the merge demo has something to re-anchor renames onto (proving structural, not id, matching).
    write(
        "mathlib_rebuilt.scylla",
        scylla_ingest::snapshot_to_program(SNAPSHOT).unwrap(),
    );
}
