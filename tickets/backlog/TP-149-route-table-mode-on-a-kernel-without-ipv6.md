---
id: TP-149
title: "Route table: route-table mode on a Linux kernel without IPv6"
milestone: M2
area: dataplane/routetable
repo: thinkpol-vpn
size: M
depends_on: [TP-135]
refs: []
owner: ""
branch: ""
---

## Goal
Route-table mode works on a Linux host booted with `ipv6.disable=1`: it applies the IPv4 layout, skips IPv6, and says so in its status, instead of failing every Apply.

## Scope
- `PolicyRouting` (internal/dataplane/routetable/routetable.go) always emits rules for both families, and IPv6 routes (the `::/0` unreachable at least). On such a kernel the first IPv6 rule add (`addKernelRule`, netcfg/rules_linux.go) returns EAFNOSUPPORT, so every Apply fails and is undone. Not a regression: TP-135 made rule dumps take EAFNOSUPPORT as an empty family (`dumpErr`), but adds still fail.
- Decide where the kernel's lack of IPv6 is learned: netcfg (e.g. a `Survey` field saying the IPv6 family has no rules or routes) or the Enforcer, and have `PolicyRouting` leave out the IPv6 rules and routes when it is gone. Check IPv6 route adds as well as rule adds.
- Report it: a routetable `Status` field (or an existing one) that says IPv6 is not handled because the kernel has none, shown in the agent's status.
- With IPv6 gone from the kernel there is nothing to leak over it; write that reasoning into routetable/doc.go.

## Out of scope
- `CONFIG_IPV6_MULTIPLE_TABLES=n` with IPv6 itself on (IPv6 traffic without policy rules): note what happens, a ticket of its own if it needs work.
- The overlay mode's netcfg use.

## Acceptance
- [ ] a lab check (a container or namespace where the IPv6 rule family is unavailable, if the lab can make one) or a unit test with a configurator that answers EAFNOSUPPORT for IPv6: Apply succeeds with the IPv4 rules and routes only, and the status says IPv6 is skipped
- [ ] on a normal kernel the layout is unchanged (existing tests)
- [ ] the Log says what could only be checked on a real `ipv6.disable=1` host, if anything
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-135 round-2 correctness review, suspicion S3.
- Depends on TP-135 for the raw rule code (`dumpErr`, `sendRule`) it builds on.
- Without TP-148, the failing Apply is retried at the 200 ms debounce.

## Log
- 2026-10-29 created in backlog (TP-135 round-2 review, S3)
