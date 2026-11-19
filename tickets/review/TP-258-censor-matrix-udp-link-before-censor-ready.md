---
id: TP-258
title: "The censor matrix's udp row brings its link up before the censor is ready"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-258
branch: tp-258-udp-link-after-censor
---

## Goal
setupUDP (lab/results_test.go ~:1407-1412) starts both agents and waits for linkUp before startCensor, so the udp link's handshake crosses the router with no censor table (TP-236's "link up 0.3 s before censord was ready"). judgedFromTheStart (lab/reality_matrix_test.go ~:369-372) checks only reality's flow, so a held udp cell (wireguard-rhythm) can't notice a censor that started mid-flow and missed the handshake that anchors the rekey timing: a possible pass for the wrong reason in an M2 gate input. Start the udp device after the censor is ready (as realityUp does), and make judgedFromTheStart take the row's flow matcher; all verdicts unchanged.

## Scope
- Start the udp row's device after "censor ready", as realityUp does for reality.
- judgedFromTheStart takes the row's flow matcher, so the udp row's held cells check their own flow.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- Found in TP-252's review: lab/censor/doc.go said every test starts its traffic after "censor ready"; the udp row is the exception.
- Root cause: setupUDP started device-a's agent and waited for its link before the cell started censord, so the udp tunnel's 5-tuple began (the path layer's probe and reply that bring a link up) with no censor table, and the censor joined it at its next datagram. Evidence: with that order brought back (mutation below) the held cell's check reads "the censor joined the tunnel already up: its first line on it (udp …:42050->…:4500) is 1.689253437s after device-a's link came up". What it missed was the probe exchange, not WireGuard's handshake: a link comes up on path probes alone and WireGuard handshakes at the first packet through the tunnel, the hold's first ping, after censord (a first draft checked that the trace's first WireGuard message is device-a's 240-byte initiation; under the old order it still passed, so that check couldn't see the cause and was dropped). So the rhythm cell's anchor was not missed; what changed is that a udp cell's flow now starts under the censor, as every other row's does (lab/censor/doc.go), which also gives fully-encrypted the link's real first datagram.
- Fix: the udp row defers device-a like reality (deferDevice in setup, deviceUp in the cell's probe or hold, shared by both rows: lab/results_test.go). judgedFromTheStart takes the row (transport.tunnel, the held connection's flow matcher: realityFlow, udpFlow): reality keeps its "stream not framed" check; for udp, seenBeforeUp requires the censor's first verdict-log line on the tunnel to be no later than device-a's link came up: the engine's own instant, the local API's neighbor `up_since` (added in review round 1, R1.1), for server-1's node id, taken from the status deviceUp's poll ended on (deferredDevice.upSince; containers share the kernel clock). A link is up only once its probe's reply came back, and the censor stamps a line when it judges a packet, before forwarding it, so a censor that saw the probe has a line from before; one that joined later can't. (Round 0 read the device's clock after `status -json` less `up_for`, late by an exec and a `date`, which could accept a censor that joined within that delay; up_since has no such slack.)
- Runs (targeted `make lab-gotest PKG=./lab`, under load: other tickets' labs and tests at once): the whole udp row (both labs, `RUN=TestCensorMatrix/^udp(_lab_[0-9]+)?$$/`) 5/5 at 400f6787 (before TP-247's split, one lab, `^udp$$/`, 2296 s), 5/5 at e9b627e2 (2119 s), 1/1 at the final merge 5ee708ed (232 s); the held cell's lab (`^udp$$/^(off|wireguard-rhythm)$$`) 5/5 (1467 s) and 10/10 (2706 s) at e9b627e2. With the final check that is 26 passing runs of the held udp × wireguard-rhythm cell and 11 of every other udp cell, each as expected: off, blocklists (elsewhere), sni-blocklist, wireguard-fingerprint, openvpn-fingerprint, active prober and server-hello pass; ip-blocklist, fully-encrypted and wireguard-rhythm fail. No known flake (TP-250's udp × fully-encrypted partial) showed. The reality row (three labs, deviceUp now shared) 1/1 at e9b627e2 (392 s).
- Verdicts: the udp row's expected verdicts are unchanged (censorCases untouched) and every run matched them. The committed lab/RESULTS.md is older than the current matrix (no reality row; udp × wireguard-rhythm `pass`, which the matrix now expects to fail): its udp cells match these runs' but that one, which isn't this ticket's change. No full lab (the brief says none): RESULTS.md isn't regenerated here.

## Review findings
Two reviewers; the order fix, the reality refactor and the comparison's direction are right. Round 1:
- [x] R1.1 (should-fix) linkUpBy computes the link's up time as `date` after `status -json` less `up_for`, which internal/dataplane/path/node.go warns against (TP-212 R1.6 rejected it): upBy is always late by an exec and a `date`, hundreds of ms under load, so the check can accept a censor that joined late. Expose the engine's own NeighborStatus.UpSince in the local API status (`up_since` on localapi's Neighbor, set in convert.go), following the status schema's rule for an added field and the API docs that list status fields, with a unit test; the lab reads it.
- [x] R1.2 (should-fix) linkUpBy runs for every deferred-device cell (all reality and udp cells), once, with no retry: an exec timeout or a link drop right after linkUp fails a pass cell (new for reality). Read it only where needed (held udp cells), inside a bounded poll; a zero upBy errors clearly ("device-a's link-up time wasn't read"); the neighbor must be server-1 (node_id), not the first one up.
- [x] R1.3 (should-fix, suspected) for udp the block watch sees a drop only through a decision line, logged once per flow/verdict/module; the link's datagrams share one 5-tuple, so if the first drop is logged before the watch's mark, deviceUp waits the full 60 s and the scored probe waits blockedWindow per family. Measure deviceUp's wait in udp × ip-blocklist and udp × fully-encrypted; if it hits the 60 s, make the udp watch count the blocker's drops since startUp (mark taken before startUp).
- [x] R1.4 (ticket) TP-250's known-flake rate (udp × fully-encrypted ~1/120) was measured with the first datagram from an already-up link; now it's the link's own probe: say in the Log that the rate predates the new order; file nothing unless the 10+ runs show a change.
- [x] R1.5 (nits) checkMatrix rejects a held row without `tunnel` up front; TestSeenBeforeUp gets a case with two matching lines (first vs last); the Log's mutation count ("`!found` never true" fails two cases).

## Log
- 2026-11-19 created in backlog (TP-252 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-258
- 2026-11-19 udp row defers device-a to the cell (deferDevice/deviceUp, shared with reality); judgedFromTheStart takes the row's tunnel matcher and, for udp, checks the censor's first verdict on the tunnel is no later than device-a's link came up (seenBeforeUp, TestSeenBeforeUp); docs: lab/README.md, lab/censor/doc.go
- 2026-11-19 mutations: setupUDP brings the link up before the censor again (deviceUp in setup) → the held cell errors "the censor joined the tunnel already up … 1.689253437s after device-a's link came up"; seenBeforeUp's After(upBy) made never true → TestSeenBeforeUp fails 2 cases; its !found case made never true → fails "empty"; a first draft's trace rule (first WireGuard message is device-a's initiation) passed under the setupUDP mutation, so it was replaced
- 2026-11-19 make lint, make test green at 5ee708ed; lab runs in Notes; no full lab (brief: none); not verified: the check's blind spot (a censor joining within the status call after the link came up)
- 2026-11-19 out of scope: lab/RESULTS.md is stale against the matrix (no reality row, udp × wireguard-rhythm pass); the next full lab regenerates it
- 2026-11-19 in-progress → review
- 2026-11-19 review → has-errors
- 2026-11-19 review round 1: fix R1.1–R1.5
- 2026-11-19 R1.1: the local API's Neighbor has `up_since` (proto field 7, set in convert.go from NeighborStatus.UpSince; an added field, so no schema_version bump, per localapi's doc "JSON"; docs: api-overview-reference.md's example and the null list there and in localapi/doc.go); TestNeighborUpSinceReachesTheStatus, mutation: UpSince dropped from convert.go → fails ("up_since <nil>"); the lab compares with it (deferredDevice.upSince), not `date` less up_for
- 2026-11-19 R1.2: no read of its own: upSince comes from the status deviceUp's poll ended on (the poll is bounded, 60 s), for server-1's node id (m0Space.nodeID), and only judgedFromTheStart's udp branch (held udp cells) reads it; a missing one errors "device-a's link-up time wasn't read: …"; TestUpSince, mutations: the node-id check dropped → 3 cases fail; the up/zero check dropped → "server-1 down" fails
- 2026-11-19 R1.3: deviceUp logs its wait; udp row ×3: ip-blocklist 7.6 s, 8.2 s, 2.7 s; fully-encrypted 8.8 s, 2.7 s, 2.7 s; never the 60 s, so the watch is unchanged. The scored probe after a blocked deviceUp still waits blockedWindow per family (those cells take 24-34 s, the others 8-14 s): bounded, left as is
- 2026-11-19 R1.4: TP-250's known-flake rate (udp × fully-encrypted ~1/120) was measured with the first datagram from an already-up link and predates the new order, where the first is the link's own probe; under the new order 14 runs (11 in round 0, 3 in round 1), all as expected, no flake: no change shown at that count, nothing filed
- 2026-11-19 R1.5: checkMatrix refuses a held row without transport.tunnel (TestCheckMatrix "held row names no tunnel", mutation: the check made never true → fails); TestSeenBeforeUp "the first line decides, not the last" (mutation: seenBeforeUp keeps the last match → fails it); correction to the round-0 mutation line: `!found` made never true fails 2 cases ("another flow only", "empty"), not 1; After(upSince) made never true fails 2
- 2026-11-19 make lint, make test green at 973f63b0; lab-gotest at 973f63b0: the udp row ×3 (`RUN=TestCensorMatrix/^udp(_lab_[0-9]+)?$$/`, 42/42 subtests pass, labs 296-463 s), the reality row ×1 (`^reality(_lab_[0-9]+)?$$/`, 16/16), the held cell's lab ×5 (`^udp$$/^(off|wireguard-rhythm)$$`, 5/5, wireguard-rhythm fails as expected each time); not rerun: the setupUDP order mutation against the up_since check (a lab mutation)
- 2026-11-19 has-errors → in-progress
- 2026-11-19 in-progress → review
- 2026-11-19 merged origin/rewrite (TP-260) in: make lint, make test green and the udp row ×1 (14/14) at 8fcc58ae
