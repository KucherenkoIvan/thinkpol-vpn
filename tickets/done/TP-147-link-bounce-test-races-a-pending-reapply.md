---
id: TP-147
title: "Lab flake: the link-bounce test races a pending re-apply"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-147"
branch: "tp-147-link-bounce-test-races-a-pending-re-apply"
---

## Goal
`TestTheOverlayComesBackAfterALinkBounce` (internal/dataplane/engine_lab_test.go) passes every time: it waits for the event it means to observe instead of reading the TUN's addresses once right after the link goes down.

## Scope
- After `ipLink("down")` the test reads `ip -o addr show` once and fails with "the TUN kept its IPv6 address going down: nothing to test" (around line 273) if the IPv6 address is still there. A re-apply already pending from the setup (interface.go, at most one per `cooldown`) can add the address back to the down link before that read, so the read sees it.
- Make the test observe the address actually going away: e.g. an `ip -6 monitor address` started in the namespace before the down, waiting for the delete of `a.v6`; or wait until the engine has no re-apply pending (`InterfaceReapplies` steady past the cooldown) before the down. Whichever is chosen, the rest of the test (MTU change, link up, wait for address and MTU 1328, pings, status) stays.

## Out of scope
- The engine's re-apply behaviour (interface.go): it is right to restore the address.

## Acceptance
- [ ] the test waits on the address's removal (or on a quiet engine) instead of a single read after the down
- [ ] `make lab-gotest PKG=./internal/dataplane RUN=TestTheOverlayComesBackAfterALinkBounce COUNT=20` passes
- [ ] mutation note in the Log: the engine not restoring the address after the bounce still fails the test, and how the race was provoked (e.g. a re-apply forced right after the down) or why it couldn't be
- [ ] `make lint`, `make test` pass

## Notes
- Seen once in a full `make lab-test` run on 2026-10-28 (during TP-121's round-2 verification); a run on the commit before had passed it.

## Log
- 2026-10-29 created in backlog (lab flake seen 2026-10-28)
- 2026-10-31 backlog → in-progress, owner: agent-tp-147
- 2026-10-31 review → done, merged into rewrite (go-paranoid: merge; nit left: the address monitor's stderr is discarded, so a monitor that exits gives no reason)
