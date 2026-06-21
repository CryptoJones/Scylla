# Scylla — Backlog

Tracked "later / someday" items that aren't on the current sprint path
([SprintPlanning.md](SprintPlanning.md)) but shouldn't be lost.

## Docs

- [ ] **Revisit the proposed architecture diagram** (`docs/proposed-scylla-architecture.drawio`).
  It's readable and hexagonal now, but the layout could be tightened — port placement on the
  rim, edge routing, balance of the driving/driven sides. A polish pass, not a redo.

## Possible future adapters (the whole point of the hexagon)

- [ ] **Evaluate the x64dbg / Scylla dynamic-analysis ecosystem as a future *producer* adapter**
  behind the engine port (DD-009/018). Found via x64dbg/**ScyllaHide** (an anti-anti-debug
  plugin — runtime, tangential to our static model) — but the relevant neighbors are the
  *dynamic* tools: **Scylla** (import reconstruction), debugger dumps, unpacked-at-runtime
  images. These don't replace the GayHydra static engine; they're a *second producer* that
  could feed runtime-resolved facts (real imports, dumped code, resolved indirect calls) into
  the **same model artifact** through the engine/binary-source ports. The narrow-waist design
  is exactly what makes "add a dynamic-analysis producer someday" a new adapter, not a rewrite.
  (Bonus: the name collision is on-brand — the RE scene loves "Scylla".)

## Security

- [ ] **Threat-model the seams before Sprint 9 / before exposing the MCP head to untrusted input.**
  Decisions are locked (DD-014 sandbox the engine producer; DD-029 inherit GayHydra's
  deserialization posture + cosign), but a focused pass on (a) the engine producer that parses
  adversarial binaries and (b) the MCP head's input surface is worth doing deliberately rather
  than only at release time.
