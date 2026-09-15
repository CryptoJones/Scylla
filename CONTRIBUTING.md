# Contributing to Scylla

Scylla follows one rule the GayHydra audit taught us: **don't recreate the PR-graveyard.**
Contributions get a fast, honest signal (DD-033).

## Principles

- **Triage SLA.** Every issue/PR gets a human response — accept, request changes, or decline
  with a reason. No silent limbo.
- **Small PRs.** One concern per PR; easier to review is faster to merge.
- **Tests ship with code.** Every behavior change ships a test.
- **The core is sacred (P5).** Changes to the domain model (`scylla-model`) and the ports get
  extra scrutiny — adapters/heads are cheap, the core is the one irreplaceable bet.
- **No domain logic in heads (P6 / DD-025).** A head is pure translation; this is enforced by
  an architecture test.

## Lanes

`bug` · `feature` · `adapter` (a new head or producer) · `docs` · `security`
(report privately — see [SECURITY.md](SECURITY.md), do **not** open a public issue).

## Prerequisites

Ensure native tools (`capnp`, `protoc`, Rust stable, `wasm32-unknown-unknown`, and Node.js) are installed. See the [Prerequisites & Building](README.md#prerequisites--building) section in `README.md` for platform-specific installation commands.

## Before you push

All PRs must pass the local verification gate:
- `cargo test --workspace` is green.
- `cargo audit` reports 0 vulnerabilities.
- `scripts/check-wasm.sh` succeeds — the consume-side core must stay WASM-able (DD-028).
- `node crates/scylla-wasm/web/verify.mjs` succeeds — browser round-trip verification.
- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean.
- `NOTICE` stays accurate if you add dependencies (Apache-2.0, DD-032).

## Repo

- Branch off the default branch; PRs target it.
- Dual-remote: GitHub (canonical) + Codeberg mirror — changes land on both.
- Commit history is the design record; see [DesignDecisions.md](DesignDecisions.md) for the
  *why* behind any structural choice before proposing to change it, and
  [ARCHITECTURE.md](ARCHITECTURE.md) for the *what* — the crate map, data flow, and dev commands.
