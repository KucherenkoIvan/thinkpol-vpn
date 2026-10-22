---
id: TP-080
title: "Links declared dead while traffic is still arriving"
milestone: M2
area: dataplane/path
repo: thinkpol-vpn
size: M
depends_on: [TP-019, TP-087]
refs: [N2, docs/design/overlay.md#data-plane-every-node-one-binary]
needs_human: macos
owner: ""
branch: ""
---

## Goal
A link is not torn down while authenticated inbound data is still flowing; liveness loss behind congestion or bulk traffic is distinguished from a genuinely silent peer, and the existing dead interval still applies when traffic stops.

## Scope
During a saturating download (device run 3, 2026-10-15), the client closed a link with "no answer to its probes within 6s" and redialed on a new port. When the exit closed its side, it logged `last_in=4ms` and `last_proof=6.41s`: authenticated packets were still arriving every few ms, but liveness probes went unanswered for 6 s, presumably lost or queued behind bulk data on a congested path. The redial mid-transfer cut the measured tunnel download from about 100 to 68 Mbit/s. Device run 4 did not hit it, but the cause is unfixed. Device run 1's step-9 drop involved the same 6 s timer, though there receiving had stopped entirely.

Implement so a link must not be declared dead while it is still receiving authenticated traffic: count successfully opened inbound data as proof of life (or equivalent), and/or prioritise probes and their answers ahead of bulk data. Keep the dead interval for links that really went silent. Add INFO logging that distinguishes the cases.

## Acceptance
- [ ] lab test: a link under a saturating flow with induced probe loss (for example, probes dropped by a filter) stays up while data flows, and is still declared dead within the dead interval once inbound traffic stops
- [ ] device checklist: a tunnel speed test shows no "link closed" mid-test

## Notes
The path package doc (internal/dataplane/path/doc.go) has the 6 s dead interval; check that the change agrees with it, and update it in the same branch.
- **Split (backlog grooming 2026-10-15):** NAT rebind / source-port change → TP-084; fast redial on network change → TP-085.
- **Run 4 itself:** the link stayed up through the speed test (status `links_up=1` before and after on both sides).

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
- 2026-10-15 docs: second trigger (port change / NAT rebind) from device run 4 analysis
- 2026-10-15 docs: redial on a network change (macOS manual session)
- 2026-10-15 docs (backlog grooming): split — this ticket keeps inbound-data proof of life; TP-084/TP-085 for the other triggers
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-019 for device checklist
- 2026-10-23 docs: waits for the `reality` transport (TP-087): the owner doesn't want plain `udp` load on the network for speed tests (TP-082 question 6)
