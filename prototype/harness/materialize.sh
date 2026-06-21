#!/usr/bin/env bash
# End-to-end (Sprint 4): binary -> GayHydra headless snapshot -> Scylla model artifact.
# Usage: materialize.sh <binary> <out.scylla>
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
