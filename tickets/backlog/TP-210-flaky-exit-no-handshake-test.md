---
id: TP-210
title: "Flaky TestAnExitThatNeverHandshakesIsExitNoHandshake under load"
milestone: M2
area: agent
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-195]
refs: []
owner: ""
branch: ""
---

## Goal
`TestAnExitThatNeverHandshakesIsExitNoHandshake` (internal/agent/status_test.go, from TP-195) passes reliably under a loaded full lab, for a known root cause, not a retry.

## Scope
- Find why health leaves ok during the test's last step: it expects health ok for 4 s under steady traffic with a 1 s exit deadline. Failed twice in full labs under load on 2026-11-12, passed alone each time.
- Fix the cause, in the test or in the health grading if the grading is wrong under scheduling delay.

## Out of scope
- Retrying, longer timeouts without a cause, skipping under load.

## Acceptance
- [ ] the root cause named in Notes, with the evidence (a log or a trace from a failing run)
- [ ] the fix; the test passes 20 times in a lab node with the machine loaded (`make lab-gotest PKG=./internal/agent/ RUN=TestAnExitThatNeverHandshakesIsExitNoHandshake COUNT=20` beside a full lab), and a mutation that reverts the fix fails it

## Notes
- A third failure, in TP-048's full lab on 590e016: health went `down` with `exit_no_handshake` during the steady-traffic step (status_test.go:1095), 3.3 s into the test.
- No longer passes alone: on 2026-11-12 on a heavily loaded machine, `make lab-gotest PKG=./internal/agent/ RUN=... COUNT=5` failed 2 of 5 on rewrite at 0c16f51 and 3 of 5 on TP-048's head, each at the same step; passing runs took 9 to 14 s, failing ones 1.3 to 4.3 s.
- Suspects: the 1 s exit deadline against a handshake or traffic sample delayed by load; the 20 ms polling loop reading a status between two updates.

## Log
- 2026-11-12 created in backlog (from TP-048's full labs)
