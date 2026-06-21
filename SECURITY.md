# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Email the maintainer (Aaron K. Clark —
`cryptojones@owasp.org`) with details and a way to reproduce. You'll get an acknowledgement
within a few days.

## Posture (DD-029 / DD-014)

Scylla parses **adversarial input** — the binaries it analyzes are hostile by assumption. The
architecture contains that risk at the seams rather than trusting the parser:

- **Sandbox the engine producer (DD-014).** The component that actually parses a binary is the
  engine (GayHydra / Ghidra), run as a separate, sandboxed **producer**. The durable Rust core
  sits *outside* that blast radius — a malformed binary can crash or abuse the engine without
  reaching the model, the ports, or the heads.
- **Inherit GayHydra's hardening (DD-029).** Scylla wraps the hardened fork, which carries the
  Rec 18/19 deserialization fixes and the Rec 33/34 IPC modernization. We do not re-introduce
  the un-hardened paths.
- **The model artifact is data, not code.** The Cap'n Proto `.scylla` artifact is parse-on-read
  with bounds; loading one never executes it.
- **Signed releases.** Release artifacts are cosign-signed, matching GayHydra.

## Seams to threat-model before exposure

Tracked in [BACKLOG.md](BACKLOG.md); to be worked deliberately, not only at release:

1. **The engine producer** — the adversarial-binary parser: sandbox boundary, resource limits,
   timeouts.
2. **The MCP head's input surface** — once agents / untrusted clients drive it, validate and
   rate-limit at the head; the core's typed errors (DD-021) keep failures contained and never
   leak engine internals.
