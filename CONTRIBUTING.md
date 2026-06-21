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

## Before you push

- `cargo test --workspace` is green.
- `cargo build --target wasm32-unknown-unknown -p scylla-port` succeeds — the consume-side
  core must stay WASM-able (DD-028). (`scripts/check-wasm.sh`.)
- `NOTICE` stays accurate if you add dependencies (Apache-2.0, DD-032).

## Repo

- Branch off the default branch; PRs target it.
- Dual-remote: GitHub (canonical) + Codeberg mirror — changes land on both.
- Commit history is the design record; see [DesignDecisions.md](DesignDecisions.md) for the
  *why* behind any structural choice before proposing to change it.
