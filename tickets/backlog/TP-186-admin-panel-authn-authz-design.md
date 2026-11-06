---
id: TP-186
title: "Admin panel: organisation, authentication and authorization (design)"
milestone: M4
area: control-plane
repo: thinkpol-vpn
size: S
depends_on: []
refs: [A6, A7, A8, docs/design/control-plane.md#control-plane-the-controller-on-go-kernel]
needs_human: decision
owner: ""
branch: ""
---

## Goal
The admin panel has a written design for how it is organised, who may sign in and what each role may see and change, so TP-042 and TP-043 can start (DESIGN.md "Open questions").

## Scope
- Agents prepare a short comparison with a recommendation; the owner picks.
- The questions: who may sign in, roles and what each may see and change, sessions, CSRF on the forms, what the canvas endpoint and its live stream expose. Overlay reachability is not access control: members' devices are on the overlay by design, and the controller holds the signing key.
- The decision goes into docs/design/control-plane.md; DESIGN.md's open question is closed; TP-042 and TP-043 get their acceptance from it.

## Out of scope
- Building the panel: TP-042. The canvas: TP-043.

## Acceptance
- [ ] the owner's decision is written in docs/design/control-plane.md, with a threat note on a member's device that can reach the panel
- [ ] DESIGN.md's "Open questions" entry points at it
- [ ] TP-042 and TP-043 are unblocked, with acceptance derived from the design

## Notes
- Source: MVP triage 2026-11-07 against PRD A6, A8 (the design TP-042 and TP-043 are blocked on).

## Log
- 2026-11-07 created in backlog (MVP triage against PRD A6, A8)
