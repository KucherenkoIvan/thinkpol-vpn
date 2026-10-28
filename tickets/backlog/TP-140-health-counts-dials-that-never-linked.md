---
id: TP-140
title: "Health counts the exits it dials: a dial that never linked is a problem"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [N2, docs/design/overlay.md#data-plane-every-node-one-binary]
owner: ""
branch: ""
---

## Goal
A device whose dialed exit never linked says so in its health, instead of `connected, health: ok`. A device with no DNS upstream to ask says so too. Lab and device verdicts, and later the kill switch, can then trust "health ok" to mean the tunnel is there.

## Scope
- Today `no_link_up` is raised only when `len(dp.Neighbors) > 0 && up == 0` (`internal/agent/status.go` ~425). `path.Node.Neighbors()` (`internal/dataplane/path/node.go` ~646–669) lists only neighbours that have a link; a pending dial (`n.dials`) without one isn't listed. So a dial that never succeeds leaves the list empty, and health stays ok.
- Count the dials: a node the device dials and has never linked to, past a deadline, raises a named problem (`no_link_up`, or a new code if the two cases should read differently; say which in Notes). Pick the deadline from what the path layer already has (the dial timeout, the 6 s dead interval) rather than a new constant.
- A missing DNS upstream ("DNS: no upstream to ask", `internal/agent/resolver.go` ~53–55, `internal/dataplane/dns/resolvconf.go` ~409) raises a named problem too, not only a log line.
- `thinkpol status` and `diag` show the new problems with the existing rendering; the problem list in the docs that name them is updated in the same branch.

## Out of scope
- Making `connect` wait for the first link: a separate question (the 2026-10-24 device run's reconnect returned `health: down: no_link_up` before the link came up 2 s later, which is the honest answer).
- Redialing on a network change: TP-085.

## Acceptance
- [ ] a unit test: a dial with no link past the deadline raises the problem; before the deadline it doesn't; a link that comes up clears it
- [ ] a unit test: no DNS upstream raises its problem; one configured clears it
- [ ] lab: a device whose only exit drops every packet reports the problem in `thinkpol status`, and `health` isn't ok
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Agent): done before the M2 lanes (disguise, censor lab, kill switch) start. M2's job is links that censors break, so health that says ok with no link makes every lab verdict unreliable.
- **Device evidence (the 2026-10-24 macOS device run, the connect-on-boot reboot).** Wi-Fi had no link during that boot. The agent logged `dial failed … netcfg: no default route (IPv4)` and `DNS: no upstream to ask`, the peer showed `no path yet  no handshake  rx 0 B`, the exit saw no handshake, and `thinkpol status` said `connected, health: ok`.
- The same logic was in place before the consolidation phase, so this isn't a regression; it was never seen because the link always came up.
- TP-144's device re-run checks the fix on the Mac (the connect-on-boot reboot with no link).

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run and code-health review: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
