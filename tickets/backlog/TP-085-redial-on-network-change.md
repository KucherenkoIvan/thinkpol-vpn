---
id: TP-085
title: "Redial at once on a network change"
milestone: M2
area: dataplane/path
repo: thinkpol-vpn
size: S
depends_on: [TP-019]
split_from: TP-080
refs: [N2, DESIGN#data-plane]
needs_human: macos
owner: ""
branch: ""
---

## Goal
After sleep/wake or a default-route change, the client redials as soon as the route survey sees the new network instead of waiting out the full probe dead interval.

## Scope
From the 2026-10-15 macOS manual session: after sleep/wake or a network change, the link is only declared dead after the 6 s probe timeout, and it comes back 1.4–3.5 s after the network returns. Redialing when the route survey sees a new default route (or the old one gone) should cut recovery to roughly the redial time. The same signal can shorten recovery in NAT-rebind cases (see TP-084).

## Acceptance
- [ ] on a route-table change that replaces the default route, the client starts a redial without waiting for the 6 s dead interval
- [ ] device checklist: after sleep/wake or Wi-Fi change, the tunnel is back within about the redial time, not dead-interval plus redial (measured: link declared dead after the 6 s probe timeout today; back 1.4–3.5 s after the network returns)

## Notes
- Split from TP-080 (backlog grooming 2026-10-15). Measured numbers from the macOS session: dead after 6 s probe timeout; recovery 1.4–3.5 s after the network returns.
- Overlaps TP-019's sleep/wake checklist only where route survey already runs; this ticket is the fast redial policy.

## Log
- 2026-10-15 created in backlog (split from TP-080, backlog grooming)
