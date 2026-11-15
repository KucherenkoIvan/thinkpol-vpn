---
id: TP-220
title: "Flaky resolv.conf settle tests under load"
milestone: M2
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-217]
refs: []
owner: agent-tp-220
branch: tp-220-flaky-resolvconf-settle-tests
---

## Goal
`TestResolvConfASlowWriterPastTheCapKeepsItsServers` and its sibling settle tests (internal/dataplane/dns/resolvconf_settle_test.go) pass reliably under load, for a named root cause, not a retry or a longer timeout.

## Scope
- They pass alone (`make lab-gotest PKG=./internal/dataplane/dns RUN=TestResolvConfA COUNT=10`: 10 of 10) and failed in 3 of 4 full-lab node phases on a Linux Docker 29 host (TP-211's runs, 2026-11-15): `TestResolvConfASlowWriterPastTheCapKeepsItsServers` each time, `TestResolvConfAWriterThatNeverSettlesIsTakenBackAtTheCap` once.
- Reproduce under load (a full lab beside it, or the SIGSTOP freezes and busy loops TP-217 used), name the cause, and fix it in the test or the code.
- First read TP-217's code (merged, or its branch while it is in review): it fixed two other tests in this package, the restore after a failed rewrite and the file renamed in, and changed when the take-over's watch starts. The settle tests may share a cause with them or with that change.

## Out of scope
- The tests TP-217 fixed.

## Acceptance
- [ ] The root cause named in Notes, with the failing run's evidence.
- [ ] A fix in the test or the code, with the docs it touches updated.
- [ ] The settle tests pass 20 runs under load (a full lab or the same freezes beside them) on Linux, and a mutation that brings the cause back fails them.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-15 created in backlog (from TP-211's and TP-197's lab runs)
- 2026-11-16 backlog → in-progress, owner: agent-tp-220
