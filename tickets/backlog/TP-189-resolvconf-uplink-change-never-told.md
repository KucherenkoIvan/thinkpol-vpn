---
id: TP-189
title: "dns: a change to resolved's uplink file alone is never told"
milestone: later
area: dataplane
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [R4]
owner: ""
branch: ""
---

## Goal
On the resolv.conf path, the caller learns about new direct upstreams when only systemd-resolved's uplink file changes, not only when resolv.conf itself does.

## Scope
- In `internal/dataplane/dns/resolvconf.go` the upstreams come from resolv.conf and, when it lists only resolved's stubs, from resolved's uplink file. A change to the uplink file alone (resolv.conf unchanged) is never seen, so the caller keeps the previous network's upstreams.
- Watch the uplink file too, or re-read it on the backstop poll, and tell the caller when the upstreams it yields change.

## Out of scope
- The systemd-resolved path (links over D-Bus).

## Acceptance
- [ ] a test changes only the uplink file and the caller is told the new upstreams
- [ ] an unchanged uplink file tells nothing
- [ ] the `dns` package doc says what is watched
- [ ] `make lint`, `make test` pass

## Notes
- Found in TP-130's round-1 review, 2026-11-07.

## Log
- 2026-11-07 created in backlog
