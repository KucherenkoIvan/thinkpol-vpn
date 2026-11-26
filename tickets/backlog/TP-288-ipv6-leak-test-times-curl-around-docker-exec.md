---
id: TP-288
title: "TestNoIPv6LeavesAroundTheTunnel times curl around a docker exec"
milestone: later
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
TestNoIPv6LeavesAroundTheTunnel's "refused at once" check measures curl itself, not the docker exec around it, so a loaded machine can't fail it while curl was refused at once.

## Scope
- lab/ipv6leak_test.go: the 4 s bound on a curl bound to a physical interface (`took > 4*time.Second`) is measured on the host around `docker exec`. Time it inside the node instead (curl's own `time_total`, or timestamps taken in the node, as TP-080's holdBlackout in lab/liveness_test.go does), and keep the bound on that.
- Check the test's other host-side wall-clock bounds (the 3 s guard bound) for the same pattern; fix them the same way or say in Notes why not.

## Out of scope
- Changing what the test checks (no IPv6 leaves around the tunnel) or the bound's value.

## Acceptance
- [ ] the curl bound is timed inside the node, not around the exec
- [ ] a mutation (curl made slow inside the node, e.g. a drop instead of a refusal on the bound interface) still fails the check; named in the Log
- [ ] `make lint`, `make test` and a targeted `make lab-gotest PKG=./lab RUN=^TestNoIPv6LeavesAroundTheTunnel$` pass

## Notes
- Seen in a TP-080 full lab on 2026-11-26: under load the exec alone took 4.27 s around a 0 ms curl refusal ("Failed to connect ... after 0 ms"), and the test failed; a targeted re-run passed.

## Log
- 2026-11-26 created in backlog (found in TP-080's full lab runs)
