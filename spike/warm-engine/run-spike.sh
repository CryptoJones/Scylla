#!/usr/bin/env bash
# Warm-engine de-risk spike runner (DD-040 follow-up). Compiles + runs Spike.java with the GayHydra
# dist jars + the engine-service grpc stack on the classpath, to test whether in-process Ghidra and
# grpc-netty-shaded coexist in one JVM. Prints the [spike] verdict lines.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GH="${GHIDRA_DIST:-/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0}"
GRPC_LIB="$ROOT/engine-service/build/install/scylla-engine-service/lib"

[ -x "$GH/support/analyzeHeadless" ] || { echo "set GHIDRA_DIST to the GayHydra dist"; exit 1; }
[ -d "$GRPC_LIB" ] || { echo "build the grpc stack first: (cd engine-service && gradle installDist)"; exit 1; }

CP="$(find "$GH" -name '*.jar' | tr '\n' ':')$(find "$GRPC_LIB" -name '*.jar' | tr '\n' ':')"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
javac -proc:none -cp "$CP" -d "$OUT" "$HERE/Spike.java"

echo "# default system classloader:"
java -cp "$OUT:$CP" -Dghidra.install.dir="$GH" Spike 2>/dev/null | grep '\[spike\]'
echo "# with GhidraClassLoader as system CL (the launcher's mode):"
java -cp "$OUT:$CP" -Dghidra.install.dir="$GH" \
  -Djava.system.class.loader=ghidra.GhidraClassLoader Spike 2>/dev/null | grep '\[spike\]'
