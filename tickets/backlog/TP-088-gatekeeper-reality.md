---
id: TP-088
title: "Gatekeeper learns `reality`"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-087, TP-063]
refs: [DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
The `reality` transport's pre-authentication parsing runs in the gatekeeper, not the root supervisor.

## Scope
- The session-id open and the splice to the target run in the gatekeeper.
- The listener's X25519 private key is the documented exception to "verifiers only" (DESIGN "Server agent").

## Out of scope
- The transport itself: TP-087.

## Acceptance
- [ ] the gatekeeper opens `reality` session ids and splices failures to the target; the root supervisor reads no unauthenticated bytes
- [ ] the seizure check lists the `reality` private key as the one exception to "verifiers only"

## Notes
- Findings: TP-064 Notes (Q3, gatekeeper).

## Log
- 2026-10-15 created in backlog (TP-064 findings)
