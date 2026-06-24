#!/usr/bin/env bash
# Harness M4 — the dynamic PRODUCER end-to-end on a benign sample, against the REAL tier.
#
# Runs the spike's `m4` path: `MicroVmHarness` (src/harness.rs) boots the M1 microVM, the M3 in-guest
# observer recovers the benign sample's resolved IAT, it crosses the M2 channel through the bounded
# validator (channel.rs), and each observed edge is stamped DD-007 `producer="dynamic"` with
# partial-coverage confidence — so DD-027 collaborate down-ranks it and the WRONG=0 matcher is never
# fed ground truth. Execute-in-sandbox → observe → channel → validate → stamp, end to end.
#
# Benign-only + contained (no egress, no host FS, capped, ephemeral). Set $KERNEL to a readable bzImage.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE_DIR="$(cd "$HERE/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH" CC="${CC:-/usr/bin/gcc}" CXX="${CXX:-/usr/bin/g++}"
cd "$SPIKE_DIR"
exec cargo run -q -- m4
