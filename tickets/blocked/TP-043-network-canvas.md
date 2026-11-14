---
id: TP-043
title: "Network canvas"
milestone: M4
area: features/topology
stream: administration
repo: thinkpol-vpn
size: epic
depends_on: [TP-042, TP-086, TP-186]
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

## Blocked by
The admin panel's organisation, authentication and authorization are not designed (DESIGN "Open questions"). TP-186 owns that design (since 2026-11-07); only the author can decide it.

## Notes
- **Don't start before the panel's design exists (TP-062).** Same as TP-042: the panel's organisation, authentication and authorization are on hold (DESIGN "Open questions"), and the canvas JSON endpoint and live stream are part of what that design must cover. The design is TP-186 (2026-11-07).

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): do not start before the panel's authn/authz design exists (blocking note)
- 2026-10-15 backlog → blocked — panel authn/authz design missing (backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): Blocked by names who can unblock
- 2026-10-15 docs: depends on TP-086 (frontend stack revisit)
- 2026-11-07 docs: the panel design is TP-186; depends on it
