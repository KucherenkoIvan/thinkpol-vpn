---
id: TP-203
title: "reality conformance: ShapingRefused fails with 'TLS handshake: EOF'"
milestone: M2
area: dataplane/transport
stream: transports
repo: thinkpol-vpn
size: M
depends_on: [TP-087]
refs: [C6, docs/design/transports.md#transports]
owner: "agent-tp-203"
branch: "tp-203-reality-conformance-shaping-refused-eof"
---

## Goal
TP-087's reality conformance test passes every time, or the product bug it exposes is fixed.

## Scope
- Find the root cause of TestConformanceShaped/random/ShapingRefused (and the earlier spelling TestConformance/ShapingRefused/2) failing with "TLS handshake: EOF": about 1 in 3 when its package runs alone in a lab node (`make lab-gotest`), seen by TP-026's implementer on 2026-11-12 and by TP-087's merge on 2026-11-09.
- Fix whichever is wrong, the test or the product. No retries, raised timeouts or skips unless the evidence shows the test's timing assumption is the only wrong thing.

## Out of scope
- Anything outside the reality package and its tests; reality behind the shared listener is TP-201.

## Acceptance
- [ ] root cause named with evidence (a failing run explained, not guessed)
- [ ] fix (test or product, whichever is wrong; if it's the product, what a real client would see is written down)
- [ ] the package passes 20 consecutive runs in a lab node
- [ ] every new or changed test mutation-checked

## Notes

## Log
- 2026-11-12 created in backlog (the reality conformance flake blocks the full lab)
- 2026-11-12 backlog → in-progress, owner: agent-tp-203
