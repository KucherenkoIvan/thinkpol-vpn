---
id: TP-270
title: "Find what leaves accept_ra at 2 after the supervisor's tests"
milestone: M2
area: dataplane/agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-270"
branch: "tp-270-accept-ra-left-at-2"
---

## Goal
After `internal/agent/supervisor`'s tests, a lab node has `net.ipv6.conf.{default,eth0,lo}.accept_ra` at 2 (clean: 1), seen by the node pool's reset (TP-269). Close restores it (`egress_linux_test.go` asserts that), so some test or crash-recovery path leaves it. If the product can leave it on a real host after the VPN stops, a server keeps taking router advertisements. Find the path, and fix the product if it is there (else the test).

## Scope
- Name the test, and the code path in it, that leaves `accept_ra` at 2 (bisect the package's tests in a lab node, reading the sysctls after each).
- If the path is the product's (a stop, a crash recovery, a forwarding put back without its `accept_ra`), fix it there; if it is only the test's, fix the test.

## Acceptance
- [ ] The cause named, with evidence (the test and the code path, the sysctls before and after).
- [ ] The fix.
- [ ] A test that fails when `accept_ra` is left changed after the path that left it.

## Log
- 2026-11-20 created in backlog (TP-269 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-270
