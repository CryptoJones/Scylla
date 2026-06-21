#!/usr/bin/env bash
# DD-034: run the engine producer (the adversarial-binary parser) in a locked-down container.
# A hostile sample can torch this sandbox without reaching the Rust core, the host FS, or — in
# the full-lockdown variant — the network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GHIDRA_DIST="${GHIDRA_DIST:-/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0}"
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$HERE/../prototype/harness" && pwd)}"
PORT="${PORT:-50051}"

exec docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,exec,size=1g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 4g --cpus 2 --pids-limit 512 \
  -e HOME=/tmp -e GHIDRA_DIST=/opt/gayhydra -e SCYLLA_SCRIPT_DIR=/opt/scripts \
  -v "$GHIDRA_DIST":/opt/gayhydra:ro \
  -v "$SCRIPT_DIR":/opt/scripts:ro \
  -p 127.0.0.1:"${PORT}":50051 \
  scylla-engine-service:dev

# `/tmp` is the one writable surface (tmpfs) and is mounted `exec` on purpose: GayHydra's
# launcher and the native decompiler extract and run code from temp, and the JVM's user.home
# points here. It is RAM-backed, size-capped, and wiped on exit — the rootfs stays read-only.
#
# DD-034 full no-egress lockdown (BACKLOG): the strongest form is `--network none` + gRPC over a
# bind-mounted unix socket, so a hostile binary literally cannot phone home. That needs UDS in
# the service + Rust client. This v1 publishes gRPC on host-loopback only and applies every
# other control: read-only rootfs, dropped caps, no-new-privileges, mem/CPU/PID limits, non-root.
