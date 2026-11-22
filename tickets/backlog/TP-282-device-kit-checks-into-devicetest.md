---
id: TP-282
title: "Move the device kit's remaining checks into lab/devicetest"
milestone: later
area: tooling
stream: verification
repo: thinkpol-vpn
size: L
depends_on: [TP-082]
refs: []
needs_human: macos
owner: ""
branch: ""
---

## Goal
Every check the old private bash device kit ran exists as a `lab/devicetest` plan, so the kit's job is done by one tool with a frozen safety core and real tests, and nothing needs the kit again. TP-082 built the harness and its first plans (TP-085, TP-096, TP-143); this ticket moves the rest, plan by plan.

## Scope
Already plans (TP-082): the self-test alone, TP-085 (a reality connect, one direct and one tunnel-bound name and a browse, captured on the physical interface), TP-096 and TP-143 (pf's listings with a skip on lo and lo0). Each remaining check below becomes a plan (or part of one), migrated one plan at a time, each with real tests where the OS allows them (a lab node for the Linux side, recorded fixtures for what only a Mac answers), and listed in `lab/devicetest/doc.go`. A plan records evidence; it never judges (docs/design/lab.md "Device testing").
- **Preflight:** no other VPN, relay or encrypted-DNS profile active; the build under test and its commit recorded.
- **Link:** connect through an exit server and record the handshake, the transport and the status over the run (TP-085 records one connect; this is the link's state through the other checks).
- **DNS:** which resolver answered each name and over which interface, from the agent's and the OS's side (TP-085 has the wire's side).
- **Sleep and wake:** the owner sleeps the Mac for a minute; the link's state recorded before and after.
- **Network change:** the owner switches networks and back; the link, routes and DNS recorded at each point.
- **Local API groups:** the group the local API checks set up, used and removed.
- **Another VPN:** another VPN started and stopped beside thinkpol; routes, DNS and the link recorded.
- **Application firewall, block-all:** the OS firewall turned on with block-all and back off by the owner; the link recorded.
- **pf guard:** a pf baseline with no thinkpol running, the guard's anchors and tables while connected, the guard undoing a flush and an extra table entry, and pf after disconnect (needs a network with native IPv6).
- **Crash:** a kill -9 of the agent, with the switch on and off; pf, routes and DNS recorded for the seconds no agent runs, and after the restart.
- **Source-bound sockets:** whether a socket bound to the physical interface's address bypasses the tunnel.
- **Route install at scale:** the time to install a domestic list of country size (tens of thousands of routes).
- **Throughput:** a speed test direct and through the tunnel.
- **Resources:** the agent's memory and CPU on the Mac, and the exit server's, sampled through the run (and during the throughput test).
- **After the restore:** a real lookup and connection, so a run ends with the Mac working.
- The exit-server driver these need, unless another ticket has built it by then: a container on the owner's server, with everything that names it read from a private file outside the repo.

## Out of scope
- Changes to the safety core (`lab/devicetest/safety`, pinned by `FROZEN`): a check that needs a new change kind gets its own ticket and the owner's approval first.
- The kit's judging code, its stub tests and its two-terminal sessions: not ported (docs/design/lab.md "Device testing").
- Judgements: a judgement that recurs becomes a Go test over a recorded fixture or a `diag` field, in the ticket that owns the behaviour.

## Acceptance
- [ ] each check in Scope is a plan (or part of one) in `lab/devicetest/plans`, or is listed in Notes as dropped with the reason
- [ ] every plan has tests that run without a device (its listing, its validation, and its Linux side in a lab node where it has one), each mutation-checked
- [ ] each plan has had one device run from a build of its branch, judged, with the evidence named in Notes
- [ ] nothing in the repo names the owner's server, devices or private paths

## Notes
- Follow-up of TP-082 (the harness, its safety core and the first plans), split off so TP-082 could merge without the full migration (owner, 2026-11-22).
- One plan a branch is fine: tick a check's line in Notes as its plan merges.

## Log
- 2026-11-22 filed (backlog), follow-up of TP-082
