//! Generate the WASM demo's sample artifact: the mathlib snapshot → a `Program` → a `.scylla`
//! model-artifact the browser loads. Run from anywhere:
//!
//!   cargo run -p scylla-wasm --example gen_sample
//!
//! Throwaway helper; the artifact it writes (`web/mathlib.scylla`) is what the demo ships.

use std::fs;
use std::path::Path;

const SNAPSHOT: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");

fn main() {
    let program = scylla_ingest::snapshot_to_program(SNAPSHOT).expect("mathlib snapshot parses");
    let bytes = scylla_port::Session::open(program).to_artifact();
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("web/mathlib.scylla");
    fs::write(&out, &bytes).expect("write sample artifact");
    println!("wrote {} ({} bytes)", out.display(), bytes.len());
}
