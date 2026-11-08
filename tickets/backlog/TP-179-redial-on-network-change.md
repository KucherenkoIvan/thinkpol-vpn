---
id: TP-179
title: "Redial at once on a network change"
milestone: later
area: dataplane/path
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-085]
split_from: TP-085
refs: [N2, D6, docs/design/overlay.md#data-plane-every-node-one-binary]
needs_human: macos
owner: ""
branch: ""
---

## Goal
After sleep/wake or a default-route change, the client redials as soon as the route survey sees the new network instead of waiting out the full probe dead interval.

## Scope
From the 2026-10-15 macOS manual session: after sleep/wake or a network change, the link is only declared dead after the 6 s probe timeout, and it comes back 1.4–3.5 s after the network returns. Redialing when the route survey sees a new default route (or the old one gone) should cut recovery to roughly the redial time. The same signal can shorten recovery in NAT-rebind cases (see TP-084).

## Out of scope
- R4's macOS DNS-leak capture: TP-085.

## Acceptance
- [ ] on a route-table change that replaces the default route, the client starts a redial without waiting for the 6 s dead interval
- [ ] device checklist: after sleep/wake or Wi-Fi change, the tunnel is back within about the redial time, not dead-interval plus redial (measured: link declared dead after the 6 s probe timeout today; back 1.4–3.5 s after the network returns)
- [ ] device, recorded not judged (ORCHESTRATION.md "Device testing (2026-10-16)"): during a Wi-Fi change, save `thinkpol diag` (TP-091) plus a capture of the physical interface. An agent judges the evidence after the run

## Notes
- Split from TP-085, 2026-11-07, owner's MVP cut.
- Measured numbers from the macOS session: dead after 6 s probe timeout; recovery 1.4–3.5 s after the network returns.
- Overlaps TP-019's sleep/wake checklist only where route survey already runs; this ticket is the fast redial policy.
- Carried over from TP-019: during the Wi-Fi change, the capture covers step 8's items (during the join: nothing but DHCP and the link's own traffic on the old interface's filter; the new service's DNS republished with `ThinkpolOverride`), and the run records step 15b (whether `route -n get <a direct IP>` ever answers utunN during the change).

## Log
- 2026-11-07 created in backlog (split from TP-085)
