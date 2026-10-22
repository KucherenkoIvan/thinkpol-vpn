---
id: TP-086
title: "Revisit frontend design and stack: admin panel and client apps"
milestone: M4
area: ui
repo: thinkpol-vpn
size: M
depends_on: []
refs: [A6, A7, A8, D2, D3, docs/design/desktop-client.md#desktop-client, docs/design/control-plane.md#control-plane-the-controller-on-go-kernel]
needs_human: decision
owner: ""
branch: ""
---

## Goal
Choose the frontend design approach and the technical stack again, before any UI is built. The admin panel and the client apps get **different frontends** (owner's decision, 2026-10-15). Today's plan (the panel server-rendered with go-kernel's `webui` and htmx, the canvas as a JS island) is provisional.

## Scope
- **Admin panel.** Complex configuration UIs, the network canvas (PRD A7: drag to edit, live health and traffic) and filtering metrics need a lot of client-side reactivity, which server-rendered htmx pages fit poorly. Compare a single-page app (for example React with a graph-editor library such as React Flow, and a metrics charting library) against the current htmx plan. Cover how it is served (embedded in the controller binary, no runtime Node), live updates (SSE/WebSocket), and the typed API from the browser: Connect-RPC generated from the same protobufs, alongside or instead of grpc-go in go-kernel's grpckit.
- **Client apps.** A separate, smaller frontend: tray menu, connect/disconnect, space switcher, kill-switch and connect-on-boot toggles, invite links. Compare desktop shells (Wails v3, Tauri 2, Electron) on size, tray support, Go fit, macOS/Windows signing, auto-update, and the trusted base next to a kill switch. A webview can't dial the agent's unix socket, so the native shell owns that connection.
- **Reuse.** What, if anything, the two frontends share (a component library, generated API types), and whether a client UI could run both in a browser and in a desktop shell.
- **Supply chain.** A JS toolchain in a Go repo, for a censorship-circumvention tool: pinned lockfile, few dependencies, built in CI, only build output embedded; a strict CSP with no remote assets.
- The result: a comparison for the owner to decide on, then the decisions written into DESIGN.md ("Desktop client", "Admin panel") and the PRD risk table, and TP-042, TP-043 and TP-049 updated to match.

## Out of scope
- Building any UI.
- The admin panel's organisation, authentication and authorization. That is a separate open question (DESIGN "Open questions"), though the stack choice should not block it.

## Acceptance
- [ ] A written comparison with sources and versions checked at the time of writing, for both the admin panel and the client apps.
- [ ] The owner's decisions recorded in DESIGN.md and the PRD risk table; TP-042, TP-043 and TP-049 point at them.

## Notes
- Part of the UX design round after the mechanics (tickets/ORCHESTRATION.md, Decisions 2026-10-15). Don't start before that round.
- Starting points from a first look (2026-10-15), all unverified: React with React Flow and Connect-RPC for the panel. For the client shell, Tauri 2 or Wails v3 over Electron (size and trusted base). Whether Wails v3's tray is stable is unchecked. A reference architecture: an open-source app that ships one React UI in the browser and in Electron, with the platform seams behind a host bridge, though it has no tray and a TypeScript backend.

## Log
- 2026-10-15 created in backlog (owner: revisit frontend choices; admin panel and client apps get different frontends)
