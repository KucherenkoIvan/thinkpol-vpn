---
id: TP-084
title: "Link survives a NAT rebind or source-port change"
milestone: M2
area: dataplane/path
repo: thinkpol-vpn
size: S
depends_on: [TP-019, TP-080]
split_from: TP-080
refs: [N2, DESIGN#data-plane-every-node-one-binary]
needs_human: macos
owner: ""
branch: ""
---

## Goal
When a peer's UDP source port changes (client redial or NAT rebind), a link is not declared dead while authenticated data from the new port is still arriving.

## Scope
Device run 4: when the client restarted on a new local port, the exit logged `link remote moved` and 0.5 s later closed the link with `no answer to its probes within 6s`, `last_in=48ms`, `last_proof=6.445s` — data from the new port was arriving, but the probe deadline was not reset on the move. Treat remote moves like continued proof of life, or re-probe promptly without waiting the full dead interval.

## Acceptance
- [ ] lab test: after a simulated remote port change with continuing inbound data, the link stays up (or recovers within one probe round, not the full 6 s dead interval)
- [ ] device checklist: redial on a new local port during an active session does not spuriously tear down the link

## Notes
- Split from TP-080 (backlog grooming 2026-10-15). Complements TP-080's inbound-data-as-proof fix.
- TP-080's original note expected one fix to cover both triggers; if TP-080's fix (inbound data as proof of life) also covers rebinds, close this as subsumed.

## Log
- 2026-10-15 created in backlog (split from TP-080, backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-019; DESIGN ref slug; subsumed-by-TP-080 note
