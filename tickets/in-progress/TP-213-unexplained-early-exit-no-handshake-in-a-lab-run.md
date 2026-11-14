---
id: TP-213
title: "The unexplained 3.3 s exit_no_handshake in TP-048's lab run"
milestone: M2
area: agent
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-210]
refs: []
owner: "agent-tp-213"
branch: "tp-213-early-exit-no-handshake"
---

## Goal
The `exit_no_handshake` that TestAnExitThatNeverHandshakesIsExitNoHandshake raised 3.3 s into a run in TP-048's full lab (2026-11-12) has a named cause, reproduced with diagnostics on.

## Scope
- TP-210's mechanism (a re-dial, then WireGuard's next retry graded against the old pending initiation) needs a retry at least 5 s after the first initiation, so it doesn't explain a failure at 3.3 s. That run's log wasn't kept.
- Reproduce under load (the lab beside a full lab, or the SIGSTOP freezes TP-210 used) with a trace of what health is graded from (link up times, pending and last initiation, last handshake), and name the cause.
- Fix it here if it is the test's; if it is the grading's, file it with the evidence.

## Out of scope
- Retries or longer timeouts without a cause.
- TP-212's re-dial edge, unless the trace shows it is the same.

## Acceptance
- [ ] The failure reproduced, or a bounded attempt that didn't reproduce it, with the trace or the run counts; evidence: the trace or counts in Notes.
- [ ] The cause named in Notes with the trace lines that show it; evidence: the trace.
- [ ] A fix with a mutation that brings the failure back, or a filed ticket for the grading; evidence: the Log.

## Notes
- Source: TP-210's Notes ("Not explained"). TP-210's earlier 1.3 s failures had no logs either; TP-210 left them to no_link_up's own tests if they were a second re-dial.

## Log
- 2026-11-14 created in backlog (from TP-210)
- 2026-11-15 backlog → in-progress, owner: agent-tp-213
