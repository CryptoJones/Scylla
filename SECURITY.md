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

## Threat model

The deliberate seam-by-seam analysis lives in **[THREAT-MODEL.md](THREAT-MODEL.md)** — trust
boundaries, the three untrusted inputs (the binary, the `.scylla` artifact, analysis-derived
text), and the mitigations + residual gaps at each seam. It surfaced four open gaps, all tracked
in [BACKLOG.md](BACKLOG.md); the highest-priority is that the MCP head does not yet delimit
attacker-controlled analysis content as untrusted — the named prompt-injection threat (DD-035).
