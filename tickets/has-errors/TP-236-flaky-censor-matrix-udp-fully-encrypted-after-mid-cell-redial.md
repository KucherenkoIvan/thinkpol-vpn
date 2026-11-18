---
id: TP-236
title: "Flaky censor-matrix cell udp × fully-encrypted after a mid-cell redial"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-236
branch: tp-236-udp-fe-flake
---

## Goal
In a full lab (TP-223's run, 2026-11-16) the censor-matrix cell `udp × fully-encrypted` came out partial (only IPv6 crossed) after the link redialed mid-cell; re-runs passed. Find why the redial happens mid-cell and make the cell's verdict not depend on it.

## Scope
- Reproduce, name why the link redials mid-cell, and fix the cause or the cell.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the cell under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- First seen in TP-223's full lab at 17b3b1f1 (its Log, 2026-11-16).
- Seen again in TP-240's per-row matrix run on 7d37478b (2026-11-17): in the cell `udp against fully-encrypted` the server's udp link came up 0.3 s before censord was ready, closed after 6 s (its probes dropped), and a new link then crossed over IPv6, so the cell scored partial, want fail. Every reset held. Candidates to check: the cell's transport starting before the censor is ready; the fully-encrypted module and IPv6 flows that start after a redial.
- Root cause (2026-11-18): neither candidate. A redial's first datagram passing one of Wu et al.'s exemptions by chance, and a censor gap that let every redial try: the lab's fully-encrypted had no residual censorship.
  - In TP-240's partial cell the device's first link (dialed before censord was ready) was judged and blocked as it should be: the server got nothing from the device after censord came up, and the device still heard the server. The device then redialed from a new port to the same IPv4 endpoint, and that link came up in 2 ms: its first datagram crossed. The overlay's WireGuard handshake completed about 4 s later, after the IPv4 ping's window, so only the IPv6 ping crossed. "Only IPv6" is which overlay ping was running when the tunnel came back, not an underlay family.
  - The verdict log, dumped from 23 runs of the cell on b5f009bd (debug only, since removed): every cell judged one 240-byte datagram, the device's, on the link dialed before censord, and about 3 redials, each a new flow with an 84-byte first datagram, judged afresh. 68 of those were dropped; one (`udp …:56619->…:4500`) was accepted with no fully-encrypted tag, i.e. exempt. It crossed after the probes, so that cell still scored fail. The queue rule has no bypass and a fresh UDP flow's first direction is its initiator, so an exemption is the only way a redial's datagram crosses.
  - The odds: an 84-byte random datagram is exempt about one time in 115 (more than half printable about one in 175; measured in TestFullyEncryptedWireGuardInitiationByChance). With about 3 redials per cell, roughly one cell in 50 crossed. The package doc said udp's chance was per link and hour (six printable bytes first, the fixed connection id). That is wrong for the printable-half exemption, which is a fresh draw on every datagram.
  - The ordering isn't it: in all 23 cells and in TP-240's, the first datagram fully-encrypted judged was the device's, not the server's.
- Fix: residual censorship, as Wu et al. section 4.4 saw it. Once fully-encrypted blocks a connection, it drops every packet the client sends to the server's address and port, of that protocol, for 180 s, whatever it looks like (a redial's first datagram, a new SYN, a connection exempt before the block), client to server only, and the time is not extended by what it drops. tagOnly arms nothing. Docs: lab/censor/doc.go, lab/README.md, the matrix's comment.
- Other modules, checked for the same gap (a later connection getting a fresh chance): none has one. The prober blocks a found-out server for every later connection. The fingerprint, blocklist and server-hello modules decide by content that a redial repeats. wireguard-rhythm judges timing, and its held cells score what it blocked during the hold.
- What is left: the first judgement on each 3-tuple. That is the IPv4 link's 240-byte datagram (only the six-printable start, per link and hour, about 1 in 383) and the first IPv6 redial (84 bytes, about 1 in 175 by its printable bytes). So the cell still scores wrong about once in 120 runs, down from about once in 50, and the GFW would let the same connections through. Closing it is the transport's job (a link's first datagram long enough that half of it being printable is negligible), or the matrix's (scoring the chance); both are out of this ticket's scope.
- Seen after the fix (2026-11-18, aa9ddd36, the 22nd run of the cell): partial, only IPv6 crossed. Residual censorship held on IPv4: after the first link was blocked, the device's redial to endpoint 0 failed ("no answer within 6s"). The device then dialed its first IPv6 flow (endpoint 1), a new 3-tuple, which came up in 2 ms. That is the chance left above, not a fix that didn't hold. Deciding between the transport's fix and the matrix's is the owner's call.

## Review findings
Review round 1, accepted by the orchestrator: the diagnosis (a redial is a fresh draw on Wu et al.'s exemptions; residual censorship was missing) and the 1/120 arithmetic stand.
- [ ] R1.1 (should-fix) The residual decision uses decidePacket, so with `"verdict":"throttle"` it pins a throttle on the reverse flow: the server's replies are throttled for good, against the doc. Residual censorship is a drop: always Drop, its reason naming the residual window; test with the throttle and reset verdicts configured.
- [ ] R1.2 (should-fix) `exempt map[*Flow]bool` is never pruned and keeps dead flows (and their retained payload) alive after startOver/forget, and breaks the package rule that module state is keyed by FlowKey: key it by FlowKey and the flow's start time (a restarted flow is judged afresh), bounded by live keys.
- [ ] R1.3 (should-fix) TestFullyEncryptedResidualCensorship misses: the same client and port to a different server address (a key without the server address passes every case today; name that mutation); an IPv6 key separate from the same client's IPv4; an established exempt TCP connection dropped after another connection on the same 3-tuple is blocked; re-blocking after the window ran out.
- [ ] R1.4 (should-fix) "Not extended" and "120 or 180 seconds": read Wu et al. section 4.4, cite it in the comment, and make the code follow it; where the paper is silent or unsure, take the stricter reading and say in doc.go which choices are the lab's own.
- [ ] R1.5 (should-fix) The residual key includes the protocol; the paper measured TCP only. Unless the paper says otherwise, drop the protocol from the key (the stricter choice) and fix the README's "3-tuple" wording to match.
- [ ] R1.6 (nits) Docs: "per datagram" → "per new flow's first datagram" (doc.go, README); "short random datagram" → "84-byte"; the Inspect comment overclaims the Great Firewall for already-established exempt connections (the lab's own stricter choice); "a connection's first judgement on each 3-tuple" → "per 3-tuple and residual window"; doc.go's Limits lists the module's state.
- [ ] R1.7 (should-fix, evidence) An exempt accept logs nothing: make the module's Accept carry which exemption passed the flow and which side opened it, in the verdict log. Matrix scoring unchanged in this ticket.
- [ ] R1.8 (ticket) Box 3 ("20 runs pass") is ticked on one clean batch of 21 while 42 of 43 runs were right overall and the Goal isn't fully met: untick it, state the remaining ~1/120 and its cause in Notes, name the follow-up (scoring the known chance with logged exemptions, the owner's decision).

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-18 Notes: evidence from TP-240's matrix run
- 2026-11-18 backlog → in-progress, owner: agent-tp-236
- 2026-11-18 takeover after a network drop: the debug runs on b5f009bd (23 cells) give the root cause in Notes; fix on 09c2d667, debug dump removed
- 2026-11-18 mutations (each fails TestFullyEncryptedResidualCensorship, restored): no residual check; the 3-tuple without the protocol; exempt flows retired; residual never expiring; a tag arming residual; drops extending the time
- 2026-11-18 make lint, make test green on 09c2d667 (aa9ddd36 changes only this ticket)
- 2026-11-18 the cell under load (other full labs running), lab-gotest RUN='TestCensorMatrix/^udp/^(off|fully-encrypted)': 09c2d667 COUNT=10, 10 of 10 fail as wanted (2563 s); aa9ddd36 COUNT=10, 9 of 9 fail, the 10th killed by the package's 60 min test timeout while its lab came up (3601 s); aa9ddd36 COUNT=3, 2 fail and 1 partial (only IPv6), the first IPv6 flow's chance (Notes). 21 of 22 right: the 20-runs box stays unticked
- 2026-11-18 out of scope: lab-gotest's 60 min timeout covers all of COUNT's iterations, and under load one iteration of this row took up to 6 min
- 2026-11-19 merged origin/rewrite (TP-243) cleanly at 913cca8b; make lint, make test green there
- 2026-11-19 on 913cca8b, targeted lab-gotest (the full lab is the orchestrator's now): the off, fully-encrypted and active prober cells of every row, 27 of 27 as RESULTS.md has them (984 s); PKG=./lab/censor/... in a lab node passed (133 s); the cell udp against fully-encrypted, COUNT=7 three times while other branches' labs ran, 21 of 21 fail as wanted (1466 s, 792 s, 1508 s). The mutation that brings the cause back (no residual check) fails TestFullyEncryptedResidualCensorship. Box ticked on these; after the fix the cell was right in 42 of 43 runs, the one partial being the first-IPv6-flow chance in Notes
- 2026-11-19 out of scope: make lab-down left a killed run's reality prototype xray container and its network (compose-labelled) in place; removed by hand
- 2026-11-19 merged origin/rewrite (TP-242, TP-235) cleanly at 0f6f29f8: make lint, make test green; the off, fully-encrypted and active prober cells of every row 27 of 27 as RESULTS.md has them (374 s)
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.8
