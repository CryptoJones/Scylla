# Agent Guidelines & Release Procedure

This document defines standard operating procedures and operational constraints for automated AI agents and assistants working in this repository.

---

## 1. Cardinal Rule: No Direct Pushes to `main`

> [!CAUTION]
> **NEVER push directly to the `main` branch.**
> All changes — including releases, hotfixes, dependency updates, and feature implementations — MUST be submitted via a Pull Request (PR) from a dedicated branch.

- Direct pushes to `main` bypass branch protections, review controls, and automated CI gates.
- Agents must never run `git push origin main` or equivalent commands targeting `main`.

---

## 2. Release & Contribution Procedure

When implementing changes or cutting a new release, follow this mandatory step-by-step workflow:

### Step 1: Branch Creation
- Ensure `main` is up-to-date:
  ```bash
  git checkout main
  git pull origin main
  ```
- Create and switch to a descriptive branch:
  ```bash
  # For releases:
  git checkout -b release/vX.Y.Z

  # For fixes or features:
  git checkout -b fix/<short-description>
  git checkout -b feat/<short-description>
  ```

### Step 2: Implementation & Semver Update
- Implement required changes preserving existing code style and architecture invariants.
- If cutting a release:
  1. Bump `version` in `Cargo.toml` (`[workspace.package]`).
  2. Sync `Cargo.lock` by running `cargo check --workspace`.
  3. Add the release entry to `CHANGELOG.md` under a new `## [X.Y.Z] — YYYY-MM-DD` section.
  4. Update compare links at the bottom of `CHANGELOG.md`.
  5. If addressing items from `BACKLOG.md` or `ARCHITECTURE_REVIEW.md`, update their statuses and tracking notes.

### Step 3: Local Verification Gate
Before committing, all required verification checks must pass cleanly:
```bash
# 1. Code formatting check (rustfmt)
cargo fmt --all -- --check

# 2. Lint checks (deny warnings)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Full workspace tests
cargo test --workspace

# 4. Security audit (zero vulnerabilities)
cargo audit

# 5. Consume-side WASM compilation check (DD-028)
./scripts/check-wasm.sh

# 6. WASM browser round-trip verification
node crates/scylla-wasm/web/verify.mjs
```

### Step 4: Staging & Committing
- Stage only relevant files:
  ```bash
  git add <files>
  ```
- Commit using conventional commit format:
  ```bash
  git commit -m "<type>(<scope>): <summary> (<issue-ref>)

  - Bullet point description of changes
  - Verification results
  - Semver / documentation bump details"
  ```

### Step 5: Push Branch & Open Pull Request
- Push the branch to `origin`:
  ```bash
  git push -u origin <branch-name>
  ```
- Create a Pull Request targeting `main` (using `gh pr create`):
  ```bash
  gh pr create --title "<PR Title>" --body "<Detailed description of changes, verification performed, and linked issues>" --base main
  ```
- Reference any linked issues (e.g. `Fixes #XX` or `Resolves #XX`).

---

## 3. General Principles for Agents

- **Preserve Documentation Integrity:** Maintain existing comments, architecture decisions, and file headers.
- **Enforce Security Guardrails:** Never introduce uncontained native dependencies or disable security boundaries (such as DD-034 sandboxing or DD-035 untrusted envelopes).
- **Clean Audit Status:** Any new dependency or version bump must maintain a clean `cargo audit` report.
