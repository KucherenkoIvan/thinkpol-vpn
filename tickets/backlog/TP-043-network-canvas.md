---
id: TP-043
title: "Network canvas"
milestone: M4
area: features/webui
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
- Choose the graph-editor library (React Flow, Svelte Flow, Cytoscape.js, …) for a JavaScript island inside a `webui` page.
- JSON endpoint and a live-update stream.
- View with live state (must); editing by dragging (should).
- Shared nodes read-only and labelled `owned by <space>`.
- Record the kernel lesson: do islands like this belong in `webui`?

## Log
- 2026-10-10 created in backlog
