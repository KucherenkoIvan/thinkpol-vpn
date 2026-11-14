---
id: TP-088
title: "Gatekeeper learns `reality`"
milestone: later
area: agent
stream: transports
repo: thinkpol-vpn
size: M
depends_on: [TP-087, TP-063]
refs: [docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
The `reality` transport's pre-authentication parsing runs in the gatekeeper, not the root supervisor.

## Scope
- The session-id open and the splice to the target run in the gatekeeper.
- The listener's X25519 private key is the documented exception to "verifiers only" (docs/design/server-agent.md).

## Out of scope
- The transport itself: TP-087.

## Acceptance
- [ ] the gatekeeper opens `reality` session ids and splices failures to the target; the root supervisor reads no unauthenticated bytes
- [ ] the seizure check lists the `reality` private key as the one exception to "verifiers only"

## Notes
- Findings: TP-064 Notes (Q3, gatekeeper).
- From TP-201 review round 1: the supervisor also checks each reality listener's target as root at every listener open (a certificate-verifying TLS dial per server name, then REALITY's detection of its records), so whoever is on the path to the target feeds bytes to root's x509 and TLS parsers (RR37); proposal: run the target check and the detection in a short-lived sandboxed helper that returns only the verdict and the learned record lengths.

## Log
- 2026-10-15 created in backlog (TP-064 findings)
- 2026-11-07 milestone → later (owner's MVP cut: follows TP-063)
- 2026-11-12 notes: the target check and detection in a sandboxed helper (TP-201 review round 1)
