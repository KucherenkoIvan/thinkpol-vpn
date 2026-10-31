---
id: TP-158
title: "Lab flake: the forged ICMP errors test loses the root's conntrack flow under load"
milestone: M2
area: agent/supervisor
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-158"
branch: "tp-158-lab-flake-forged-icmp-errors-conntrack-flow-expires"
---

## Goal
`TestForgedICMPErrorsAreRefused/bound=true` (internal/agent/supervisor/egress_linux_test.go) passes under a full, loaded lab run.

## Scope
- Seen 2026-10-29 in a full lab run: "the root's conntrack flow expired before the forged errors were counted: the test proves nothing". It passed on re-run. TP-120 already moved the root's dial to just before the errors are sent.
- Likely cause: the root's UDP flow is unreplied, so it expires after `nf_conntrack_udp_timeout` (30 s by default), and the bound case waits up to 15 s each in two `awaitDrops` calls before `rootFlowTracked` checks it.
- Fix direction, say which in Notes: keep the flow alive while waiting (a write from the root's socket refreshes it), raise the UDP timeout in the test's namespace, or shorten the waits. The check that the flow is still tracked stays: without it the test proves nothing.

## Out of scope
- Other flakes: TP-120, TP-147.

## Acceptance
- [x] the test passes `make lab-gotest PKG=./internal/agent/supervisor/... COUNT=20` with another lab or `make test` loading the host
- [x] the `rootFlowTracked` check still fails the test when the flow is gone (mutation: never refreshing the flow and an artificial wait past the timeout fails it)
- [x] `make lint`, `make test` pass

## Notes
- Source: full lab run, 2026-10-29.
- Fix direction: keep the flow alive. The root's socket writes once a second while the two drop waits run (nothing answers the flow, so each write resets its 30 s unreplied timeout). Such a write would consume a forged error from the socket (sk_err), so a failing write fails the test as a forged error that reached the root. Raising the namespace's UDP timeout would only move the bound; shortening the waits would make them load-sensitive.

## Review findings
- [ ] R1.1 (should-fix) stop the refresh goroutine in a defer on every exit path, before root.Close
- [ ] R1.2 (nit) fail if the gap since the previous refresh write ever exceeds ~20 s
- [ ] R1.3 (nit) fix the comment on a failed write ("the refresh reports it", not "fails the test here")
- [ ] R1.4 (nit) "(30 s)" → "(30 s by default)"
- [ ] R1.5 (nit, optional) ticket Log move-line format per tickets/README.md

## Log
- 2026-10-29 created in backlog (lab flake seen in a full run)
- 2026-10-31 backlog → in-progress, owner: agent-tp-158
- 2026-10-31 cause confirmed from the code: the root's flow gets one packet (the write before SetSpaces), nothing replies, and the two 15 s awaitDrops (each can overrun its deadline by a slow nft poll) together reach the 30 s UDP timeout before rootFlowTracked runs
- 2026-10-31 fix in egress_linux_test.go: a goroutine refreshes the flow with a write each second until the drops are counted; a failed write fails the test ("a forged ICMP error reached the root's socket"); commit 547bbb2
- 2026-10-31 mutations, lab, bound=true: (A) no refresh plus a 35 s sleep before rootFlowTracked fails with "the root's conntrack flow expired"; (B) refresh on with the same 35 s sleep passes; (C) unbound accepts with the drop waits replaced by a 3 s sleep fails in the refresh write ("write: message too long", the forged fragmentation needed)
- 2026-10-31 `make lab-gotest PKG=./internal/agent/supervisor/... RUN=TestForgedICMPErrorsAreRefused/bound=true COUNT=20`: 20/20 pass on an idle host, and 20/20 again with 27 other tplab containers up and `go test ./...` looping on the host
- 2026-10-31 make lint, make test green; full make lab-test (LAB_P=4, no other labs) green on 547bbb2
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 1 should-fix, 4 nits)
