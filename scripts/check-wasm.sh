#!/usr/bin/env bash
# DD-028: prove the consume-side core (model + schema + client port) builds for the browser.
# The heavy producers (engine/ingest/MCP-head) are intentionally NOT in this set.
set -euo pipefail
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
cd "$(dirname "$0")/.."
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --target wasm32-unknown-unknown -p scylla-port
echo "OK: consume-side core builds for wasm32-unknown-unknown (DD-028 — WASM serving core)."
