#!/usr/bin/env bash
# DD-034 + GAP-1: run the engine producer (the adversarial-binary parser) FULLY locked down.
# No network namespace at all (`--network none`) — gRPC rides a bind-mounted Unix socket — so a
# hostile sample can torch the sandbox without reaching the Rust core, the host FS, OR the
# network. It literally cannot phone home.
set -euo pipefail

if [[ -z "${GHIDRA_DIST:-}" ]]; then
  echo "error: GHIDRA_DIST is required; set it to an unpacked Ghidra or GayHydra distribution" >&2
  echo "       (the directory containing support/analyzeHeadless)" >&2
  exit 2
fi
if [[ "$GHIDRA_DIST" != /* ]]; then
  echo "error: GHIDRA_DIST must be an absolute path: $GHIDRA_DIST" >&2
  exit 2
fi
if [[ ! -x "$GHIDRA_DIST/support/analyzeHeadless" ]]; then
  echo "error: GHIDRA_DIST does not contain executable support/analyzeHeadless: $GHIDRA_DIST" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required to run the sandboxed engine service" >&2
  exit 2
fi

# A host-private dir for the gRPC socket, shared with the container. World-writable so the
# container's uid 10001 can create the socket and the host client (a different uid) can connect.
SOCK_DIR="${SOCK_DIR:-$(mktemp -d)}"
if [[ "$SOCK_DIR" != /* ]]; then
  echo "error: SOCK_DIR must be an absolute path: $SOCK_DIR" >&2
  exit 2
fi
mkdir -p "$SOCK_DIR"
chmod 777 "$SOCK_DIR"
echo "engine socket: unix:$SOCK_DIR/engine.sock" >&2
echo "  client: scylla materialize unix:$SOCK_DIR/engine.sock <binary> <out.scylla>" >&2

exec docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec,size=1g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory "${SCYLLA_SANDBOX_MEM:-4g}" --cpus "${SCYLLA_SANDBOX_CPUS:-2}" --pids-limit 512 \
  -e HOME=/tmp -e GHIDRA_DIST=/opt/ghidra -e SCYLLA_ENGINE_UDS=/run/scylla/engine.sock \
  -e SCYLLA_ENGINE_WARM="${SCYLLA_ENGINE_WARM:-}" \
  -e SCYLLA_ENGINE_WARM_POOL="${SCYLLA_ENGINE_WARM_POOL:-}" \
  -e SCYLLA_ENGINE_TIMEOUT_SEC="${SCYLLA_ENGINE_TIMEOUT_SEC:-}" \
  -e SCYLLA_ENGINE_COLD_CONCURRENCY="${SCYLLA_ENGINE_COLD_CONCURRENCY:-}" \
  -v "$GHIDRA_DIST":/opt/ghidra:ro \
  -v "$SOCK_DIR":/run/scylla:rw \
  scylla-engine-service:dev

# SCYLLA_SANDBOX_MEM / SCYLLA_SANDBOX_CPUS (defaults 4g / 2) size the resource caps for a bigger
# warm pool or a higher SCYLLA_ENGINE_COLD_CONCURRENCY (e.g. the abtest harness materializing
# several binaries at once). They only move the ceiling — every other lockdown knob is unchanged.
#
# WARM ENGINE (DD-040), opt-in: run with `SCYLLA_ENGINE_WARM=1 ./run-sandboxed.sh` to keep resident
# engine JVM(s) warm in-process (~2s/call vs ~6s cold). `SCYLLA_ENGINE_WARM_POOL=N` runs N workers
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
