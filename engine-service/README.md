# Scylla engine service

The engine service is Scylla's primary binary-to-model producer. It runs GayHydra in a locked-down
container and exposes gRPC over a Unix-domain socket; the Rust CLI consumes that socket and writes
the resulting `.scylla` artifact.

## Prerequisites

- JDK 21 and Gradle, to build the Java service
- Docker, to run the DD-034 sandbox
- An unpacked GayHydra distribution containing an executable `support/analyzeHeadless`
- The Rust workspace built if you want to invoke the `scylla` CLI

`GHIDRA_DIST` must point to the unpacked distribution itself, not the archive or its parent
directory. There is intentionally no machine-specific default.

## Build

From this directory:

```sh
gradle --no-daemon installDist
docker build -t scylla-engine-service:dev .
```

The Docker build copies `build/install/scylla-engine-service`, so run `installDist` first whenever
the service, scripts, or warm-worker sources change.

## Run and materialize

Start the sandbox and leave it running:

```sh
GHIDRA_DIST=/absolute/path/to/gayhydra-distribution ./run-sandboxed.sh
```

The launcher prints the generated endpoint, for example
`unix:/tmp/tmp.example/engine.sock`. In another terminal, pass that exact endpoint to the CLI:

```sh
cargo run -p scylla-cli -- materialize \
  unix:/tmp/tmp.example/engine.sock \
  /absolute/path/to/input-binary \
  output.scylla
```

Set `SOCK_DIR` when a stable socket location is preferable:

```sh
SOCK_DIR=/absolute/path/to/private/socket-dir \
GHIDRA_DIST=/absolute/path/to/gayhydra-distribution \
./run-sandboxed.sh
```

## Runtime options

- `SCYLLA_ENGINE_WARM=1` keeps a GayHydra JVM resident for lower per-call latency.
- `SCYLLA_ENGINE_WARM_POOL=N` selects the number of resident workers.
- `SCYLLA_ENGINE_TIMEOUT_SEC=N` bounds one materialization; the service default is 300 seconds.
- `SCYLLA_ENGINE_COLD_CONCURRENCY=N` caps concurrent cold GayHydra processes.

Each worker is a full JVM. Size the warm pool and concurrency for the launcher's 4 GiB memory and
2-CPU limits, or adjust those explicit container limits locally.

## Security boundary

`run-sandboxed.sh` launches with no network, a read-only root filesystem, dropped capabilities,
`no-new-privileges`, resource limits, a non-root user, and a temporary writable filesystem. The
GayHydra distribution is mounted read-only. Do not bypass this launcher for hostile binaries
unless an equivalent isolation boundary is in place.
