#!/usr/bin/env bash
# Dynamic-analysis producer SEAM de-risk spike (NOT the harness). Loads the static .scylla model,
# ingests a SYNTHETIC resolved-IAT runtime artifact (runtime-iat.json — nothing is executed),
# merges it against the static model BY StableId, and prints the [dyn] uplift + a GO/NO-GO verdict.
# Proves the SEAM only; the execution-containment harness is explicitly out of scope (SPIKE-REPORT.md).
#
# Usage: run-spike.sh [static-model.scylla]   (defaults to the committed mathlib fixture)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
# ronin28: the real cc is shadowed by a TTY-only wrapper — point at gcc for any C build dep
# (none in this spike, but the model crates' capnp build is safe with it). See the OMI note.
export CC="${CC:-/usr/bin/gcc}" CXX="${CXX:-/usr/bin/g++}"

if [ "$#" -ge 1 ]; then
  cargo run --quiet --manifest-path "$HERE/Cargo.toml" -- "$1"
else
  cargo run --quiet --manifest-path "$HERE/Cargo.toml"
fi
