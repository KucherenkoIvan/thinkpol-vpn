---
id: TP-080
title: "Path liveness rides on data; idle probes back off"
milestone: M2
area: dataplane/path
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-019, TP-087]
refs: [RR65, N2, docs/design/overlay.md#data-plane-every-node-one-binary]
needs_human: macos
owner: "agent-tp-080"
branch: "tp-080-path-liveness"
---

## Goal
thinkpol's own path probes run every ~1.2–2 s in both directions for as long as a link is up, always the same size (507-byte records inside reality), even on an idle tunnel. A long-lived TLS connection with identical tiny exchanges every second or two is a visible tell (TP-223's idle trace, 2026-11-16). Owner, 2026-11-16: "dead link detection is important for fast switching when data is flowing through it. if liveness checks piggyback on data it's nearly instant. slower dead-link detection when idle is acceptable."

## Scope
Today: `Options.ProbeInterval` and `Options.DeadAfter` (internal/dataplane/path/node.go:22-30); `tick` (internal/dataplane/path/link.go:434-447) closes a link after DeadAfter without proof (:440) and probes it every ProbeInterval (:445-446); proof of life is only a reply to the link's own probe (`lastProof`, link.go:132-136, set by `proven`, :193-201); the package doc states the cadence: 2 s, dead after three intervals (internal/dataplane/path/doc.go:53-59).

- While data flows, liveness comes from the data itself: traffic received on a link proves it alive, and a link that sends without receiving is suspected as fast as today or faster; no standalone probes while data flows both ways.
- When a link is quiet, probes back off with random jitter to a bounded maximum interval, so an idle link shows no fixed rhythm; a dead idle link is detected within a stated bound (slower than while sending is acceptable).
- A short design section first (docs/design/, path liveness) with the cadences, bounds and how they line up with the chains design's dead-link deadlines (docs/design/chains.md on the M3 design branch, not yet approved), reviewed and shown to the owner before code.

## Acceptance
- [x] The design section reviewed and shown to the owner before code (marked "(owner, date)" once approved). Approved (owner, 2026-11-22).
- [ ] While data flows both ways, no standalone probe records are sent (lab: capture on udp, probe counters on reality).
- [ ] A dead link under traffic is detected within the design's bound, no slower than today (lab test with the number).
- [ ] On an idle link, probes back off with jitter to the design's maximum interval, and a dead idle link is detected within the stated bound (lab test).
- [ ] The censor matrix's idle rhythm case (pulled from the matrix by TP-223 pending this) is back and passes for reality and udp, with a lab TLS pinger as the control.
- [ ] RR65 and the path docs updated.

## Notes
The path package doc (internal/dataplane/path/doc.go) has the 6 s dead interval; check that the change agrees with it, and update it in the same branch.
- **Split (backlog grooming 2026-10-15):** NAT rebind / source-port change → TP-084; fast redial on network change → TP-085 (since 2026-11-07: TP-179).
- **Run 4 itself:** the link stayed up through the speed test (status `links_up=1` before and after on both sides).
- **Widened 2026-11-16:** the original goal, not declaring a link dead while authenticated data still arrives (device run 3), is the first Scope bullet: received traffic proves a link alive.
- TP-031's Notes already ask for jittered probe intervals and skipping probes on links that carried data recently; this ticket does that for every link.
- Related shaping work: TP-237 (reality hides WireGuard's handshake rhythm with cover records).

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
- 2026-10-15 docs: second trigger (port change / NAT rebind) from device run 4 analysis
- 2026-10-15 docs: redial on a network change (macOS manual session)
- 2026-10-15 docs (backlog grooming): split — this ticket keeps inbound-data proof of life; TP-084/TP-085 for the other triggers
- 2026-10-15 docs (backlog grooming, review fixes): depends_on TP-019 for device checklist
- 2026-10-23 docs: waits for the `reality` transport (TP-087): the owner doesn't want plain `udp` load on the network for speed tests (TP-082 question 6)
- 2026-11-07 milestone → later (owner's MVP cut: robustness; re-check once reality runs)
- 2026-11-07 notes: fast redial is TP-179 now (split from TP-085)
- 2026-11-16 widened and moved to M2: liveness rides on data, idle probes back off (owner, 2026-11-16)
- 2026-11-22 backlog → in-progress, owner: agent-tp-080, branch: tp-080-path-liveness
- 2026-11-22 acceptance approved (owner)
- 2026-11-22 design section written (docs/design/path-liveness.md; linked from DESIGN.md and the path package doc), waits for review and the owner
- 2026-11-22 design r2 after review (go-paranoid, pocket-torvalds, Grok: fix first): acks in frames (seq/ack) settle B1–B3; drawn suspect rule, one idle draw per transport, sibling probes, RTT-sized T, chains reconciled; three owner questions rewritten with costs
- 2026-11-22 design r3 after delta check (paranoid: fix first): budgets carry both ends' Shaping.MaxDelay (S's top shrinks by D, so under traffic ≤ max(4.5 s, 3.5 s + D), never slower than today); every old-format probe flags acks; relays fall back to kind 1 for packets with no room; close notice for receive-only ends, unhinted bound stated (26 s / 16 s); suspect only after S + R with no answer; one fresh clock per answer; one answer rule restarts the idle wait; Q3 rewritten with both options' costs (recommend back-off everywhere); Scope bullet 1 reversal stated at the top; serial seq; tell table and nits
- 2026-11-22 design r4 after delta check (fix first, narrow): a burst's first frame is itself due within S + R (no once-per-answer fresh clock), so a sparse sender is found X + 2.0–4.5 s after its last answer (X = 2/5/7 s: 4.0–6.5/7.0–9.5/9.0–11.5 s; a SYN 2.0–4.5 s after it, ≤ 8.0 s if sent within 0.5 s of an answer), priced against today's 6.5 s; "never slower than today" qualified (continuous traffic with D ≤ 3 s, or pauses ≤ 2 s with D ≤ 1 s); shaped-link probing under two-way traffic in the summary and tell table; second and sibling probes only while unanswered
- 2026-11-22 design approved (owner, 2026-11-22): Q1 (a) a lab-only TLS pinger as the idle case's control, Q2 (a) idle draws 8–24 s on reality and 5–14 s on udp, Q3 (a) every link backs off
- 2026-11-22 acceptance 2 and 5 reworded per the approved design (owner, 2026-11-22)
