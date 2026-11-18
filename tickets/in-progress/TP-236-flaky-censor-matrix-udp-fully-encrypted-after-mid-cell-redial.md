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
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the cell under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

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

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-18 Notes: evidence from TP-240's matrix run
- 2026-11-18 backlog → in-progress, owner: agent-tp-236
- 2026-11-18 takeover after a network drop: the debug runs on b5f009bd (23 cells) give the root cause in Notes; fix on 09c2d667, debug dump removed
- 2026-11-18 mutations (each fails TestFullyEncryptedResidualCensorship, restored): no residual check; the 3-tuple without the protocol; exempt flows retired; residual never expiring; a tag arming residual; drops extending the time
