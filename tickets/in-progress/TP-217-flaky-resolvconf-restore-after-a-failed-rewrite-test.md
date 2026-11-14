---
id: TP-217
title: "Flaky TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal under load"
milestone: M2
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-117]
refs: []
owner: "agent-tp-217"
branch: "tp-217-flaky-resolvconf-restore-test"
---

## Goal
`TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal` (internal/dataplane/dns/resolvconf_settle_test.go, from TP-117) passes reliably under load, for a named root cause, not a retry.

## Scope
- It failed once in `make test` under load (seen by TP-208's implementer, 2026-11-12). Reproduce it under load (the SIGSTOP freezes TP-210 used, or `-count` beside a full lab), name the cause, and fix it in the test or in the code.

## Out of scope
- Retries, longer timeouts without a cause, skipping under load.

## Acceptance
- [ ] The root cause named in Notes, with the evidence (a log or a trace from a failing run).
- [ ] The fix; the test passes 20 times under the same load, and a mutation that reverts the fix fails it; evidence: the Log.
- [ ] `make lint`, `make test` pass.

## Notes
- Source: TP-117 (merged with it); the failure was reported by TP-208's implementer.

## Log
- 2026-11-14 created in backlog (from TP-117)
- 2026-11-14 backlog → in-progress, owner: agent-tp-217
