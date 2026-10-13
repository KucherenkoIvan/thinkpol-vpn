---
id: TP-043
title: "Network canvas"
milestone: M4
area: features/topology
repo: thinkpol-vpn
size: epic
depends_on: [TP-042]
refs: [A7]
needs_human: decision
owner: ""
branch: ""
---

## Goal
The network drawn like Packet Tracer: nodes, links, transports and chains, with live state, and later editing.

## Scope (split before starting)
- The island's assets go in `shared/infra/webui`; its JSON endpoint and live stream in the features' `adapters/http`.
- Choose the graph-editor library (React Flow, Svelte Flow, Cytoscape.js, …) for a JavaScript island inside a `webui` page.
- JSON endpoint and a live-update stream.
- View with live state (must); editing by dragging (should).
- Shared nodes read-only and labelled `owned by <space>`.
- Record the kernel lesson: do islands like this belong in `webui`?

## Notes
- **Don't start before the panel's design exists (TP-062).** Same as TP-042: the panel's organisation, authentication and authorization are on hold (DESIGN "Open questions"), and the canvas JSON endpoint and live stream are part of what that design must cover.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): do not start before the panel's authn/authz design exists (blocking note)
