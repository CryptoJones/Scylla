#!/usr/bin/env bash
# Build the WASM head and stage the browser demo (web/scylla_wasm.wasm + web/mathlib.scylla).
# Needs the wasm32 target: rustup target add wasm32-unknown-unknown
set -euo pipefail
cd "$(dirname "$0")"

cargo build -p scylla-wasm --target wasm32-unknown-unknown --release
cp ../../target/wasm32-unknown-unknown/release/scylla_wasm.wasm web/scylla_wasm.wasm
cargo run -q -p scylla-wasm --example gen_sample   # regenerate web/mathlib.scylla

echo
echo "built web/scylla_wasm.wasm + web/mathlib.scylla"
echo "  serve : (cd web && python3 -m http.server)  →  http://localhost:8000"
echo "  verify: node web/verify.mjs"
