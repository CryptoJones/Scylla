#!/usr/bin/env bash
# OFFLINE materialization: binary -> GayHydra headless snapshot JSON -> Scylla model artifact.
# Usage: materialize.sh <binary> <out.scylla>
#
# The PRIMARY path is the engine port over gRPC:
#   scylla materialize <engine-endpoint> <binary> <out.scylla>   (crates/scylla-cli)
# which drives the sandboxed engine-service and consumes the Materialize stream straight into the
# artifact — no intermediate snapshot file, no second path. Use THIS script only for dev / corpus
# work when you don't want to stand up the service.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

BIN="${1:?usage: materialize.sh <binary> <out.scylla>}"
OUT="${2:?usage: materialize.sh <binary> <out.scylla>}"

INGEST="$ROOT/target/debug/scylla-ingest"
[ -x "$INGEST" ] || ( cd "$ROOT" && cargo build -q -p scylla-ingest )

SNAP="$(mktemp --suffix=.scylla-snapshot.json)"
trap 'rm -f "$SNAP"' EXIT
"$HERE/snapshot.sh" "$BIN" "$SNAP" >/dev/null
"$INGEST" "$SNAP" "$OUT"
