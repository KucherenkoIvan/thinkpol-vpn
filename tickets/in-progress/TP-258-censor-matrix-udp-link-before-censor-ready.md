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
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- Found in TP-252's review: lab/censor/doc.go said every test starts its traffic after "censor ready"; the udp row is the exception.
- Root cause: setupUDP started device-a's agent and waited for its link before the cell started censord, so the udp tunnel's 5-tuple began (the path layer's probe and reply that bring a link up) with no censor table, and the censor joined it at its next datagram. Evidence: with that order brought back (mutation below) the held cell's check reads "the censor joined the tunnel already up: its first line on it (udp …:42050->…:4500) is 1.689253437s after device-a's link came up". What it missed was the probe exchange, not WireGuard's handshake: a link comes up on path probes alone and WireGuard handshakes at the first packet through the tunnel, the hold's first ping, after censord (a first draft checked that the trace's first WireGuard message is device-a's 240-byte initiation; under the old order it still passed, so that check couldn't see the cause and was dropped). So the rhythm cell's anchor was not missed; what changed is that a udp cell's flow now starts under the censor, as every other row's does (lab/censor/doc.go), which also gives fully-encrypted the link's real first datagram.
- Fix: the udp row defers device-a like reality (deferDevice in setup, deviceUp in the cell's probe or hold, shared by both rows: lab/results_test.go). judgedFromTheStart takes the row (transport.tunnel, the held connection's flow matcher: realityFlow, udpFlow): reality keeps its "stream not framed" check; for udp, deviceUp records when device-a's link came up at the latest (its clock after `status -json`, less the neighbor's up_for; containers share the kernel clock), and seenBeforeUp requires the censor's first verdict-log line on the tunnel to be no later. A link is up only once its probe's reply came back, so a censor that saw the probe has a line from before; one that joined later can't. Blind spot: a censor that joined within the status call's own duration (tens of ms) after the link came up and saw a datagram in it.

## Log
- 2026-11-19 created in backlog (TP-252 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-258
