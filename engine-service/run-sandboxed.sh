#!/usr/bin/env bash
# DD-034 + GAP-1: run the engine producer (the adversarial-binary parser) FULLY locked down.
# No network namespace at all (`--network none`) — gRPC rides a bind-mounted Unix socket — so a
# hostile sample can torch the sandbox without reaching the Rust core, the host FS, OR the
# network. It literally cannot phone home.
set -euo pipefail
GHIDRA_DIST="${GHIDRA_DIST:-/home/hermes/Source/repos/GayHydra/build/dist/ghidra_26.3.0_GayHydra-26.3.0}"
# A host-private dir for the gRPC socket, shared with the container. World-writable so the
# container's uid 10001 can create the socket and the host client (a different uid) can connect.
SOCK_DIR="${SOCK_DIR:-$(mktemp -d)}"
chmod 777 "$SOCK_DIR"
echo "engine socket: unix:$SOCK_DIR/engine.sock" >&2
echo "  client: scylla materialize unix:$SOCK_DIR/engine.sock <binary> <out.scylla>" >&2

exec docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec,size=1g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 4g --cpus 2 --pids-limit 512 \
  -e HOME=/tmp -e GHIDRA_DIST=/opt/gayhydra -e SCYLLA_ENGINE_UDS=/run/scylla/engine.sock \
  -e SCYLLA_ENGINE_WARM="${SCYLLA_ENGINE_WARM:-}" \
  -e SCYLLA_ENGINE_WARM_POOL="${SCYLLA_ENGINE_WARM_POOL:-}" \
  -v "$GHIDRA_DIST":/opt/gayhydra:ro \
  -v "$SOCK_DIR":/run/scylla:rw \
  scylla-engine-service:dev

# WARM ENGINE (DD-040), opt-in: run with `SCYLLA_ENGINE_WARM=1 ./run-sandboxed.sh` to keep resident
# GayHydra JVM(s) warm in-process (~2s/call vs ~6s cold). `SCYLLA_ENGINE_WARM_POOL=N` runs N workers
# for N-way CONCURRENT materialize (default 1) — each worker is a full Ghidra JVM, so size N to the
# `--memory` budget below (the default 4g comfortably holds 1–2). It compiles + runs entirely inside
# the locked-down container — the worker classes land on the writable, exec, RAM-backed /tmp tmpfs
# and read the RO dist mount; no extra capability, no network, the lockdown below is unchanged.
#
# THE FULL DD-034 LOCKDOWN (GAP-1 closed): `--network none` removes every interface but loopback,
# so there is no published port and no route out; gRPC travels over a Unix socket on the
# bind-mounted, host-private $SOCK_DIR. `/tmp` stays the one writable tmpfs (exec, RAM-backed,
# size-capped, wiped on exit) the launcher + native decompiler need; the rootfs is read-only;
# caps dropped; no-new-privileges; mem/CPU/PID-capped; non-root uid 10001. No host FS, no
# privilege, no core access, NO egress.
