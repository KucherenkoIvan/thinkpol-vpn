---
id: TP-069
title: "Replays accepted after a supervisor restart"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: []
refs: [C1, C3, C6, docs/design/transports.md#transports]
owner: "agent-tp-069-fix1"
branch: "tp-069-replays-after-supervisor-restart"
---

## Goal
After a supervisor restart, datagram replays within the freshness window do not open links or reach workers in a way that enables active probing.

## Scope
- Address replay acceptance across supervisor restarts. Workers die with the supervisor (`Pdeathsig` at `supervisor_linux.go:859`, re-armed in `sandbox_linux.go:75`); sender and replay state are not persisted (`shared.go:284-290` builds fresh Routers; `RuntimeDir` holds only `forwarding.json`). The second filter `udp/router.go:24-26` assumes a still-running worker Listener; after restart the WireGuard device has no timestamp history either and answers a replayed initiation.
- Pick one approach (implementer chooses; record the decision in docs/design/server-agent.md):
  - persist per-credential sender state across restarts;
  - hold listeners closed for one clock window after a start;
  - document the caveat in docs/design/server-agent.md and RESIDUAL-RISKS.md RR34.

## Out of scope
- TLS stream replay cache behaviour (separate transport path).
- TP-036 key-epoch recovery.

## Acceptance
- [x] the chosen mitigation is implemented or documented per Scope, with the decision recorded in docs/design/server-agent.md
- [x] a test: supervisor restart followed by a replay of a captured datagram does not deliver to the worker / does not answer as a fresh initiation (per the chosen approach)

## Notes
- **Independent review (2026-10-15):** replays pass for five minutes after every supervisor restart; a fresh WireGuard device answers them — the active-probing oracle docs/design/server-agent.md rules out. References: `supervisor_linux.go:859`, `sandbox_linux.go:75`, `shared.go:284-290`, `udp/router.go:24-26`. No test covered a restart before this ticket.
- **TP-063:** replay and sender state live wherever the pre-auth filter lives after the gatekeeper move; coordinate tests with TP-070 so they are re-homed, not duplicated.

## Review findings
Round 1 reviews (correctness, design, style), orchestrator's list; nothing blocking, five should-fix.

- [ ] R1.1 The start cutoff follows the wall clock: derive it at admission as now minus the monotonic time since the start, so an NTP step after a start neither refuses every dialer nor lets captures from the gap through. Test it with a wall step after the start. Fix the runbook's clock advice if it's now wrong.
- [ ] R1.2 No start rule in a forwarded Listener (ListenForwarded): the Router in front is the gate; behind it the rule only refuses a lagging dialer after each worker restart or listener reopen and drops queued datagrams. Test: a forwarded Listener opened after a datagram was sealed still accepts it; "a worker restart loses nothing" true again.
- [ ] R1.3 server-agent.md doesn't overclaim "across restarts": state the rule, its residual (the start's own second, a sender clock ahead) and its cost.
- [ ] R1.4 RR34 names the clock dependence: a node that starts behind before NTP syncs is open; what a clock step (spoofed NTP included) does and doesn't do after R1.1.
- [ ] R1.5 Keep accepting the start's own second, with the real reason (genuine traffic in the first second after a start, the real-clock tests and conformance suite), and say a restart that finishes within a second leaves that second's captures open.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): Pdeathsig cite fixed; note on TP-063 filter location
- 2026-10-31 backlog → in-progress, owner: agent-tp-069
- 2026-10-31 decided: a udp table receiver (Listener, Router) refuses every datagram sealed before the Unix second it started in (`udp/admit.go` startedAt; counted as a stale timestamp, verdict Stale, to the camouflage). The dialer has no such rule. Rejected: persisting sender state (writes each credential's activity to the node's disk, against Node safety); holding listeners closed for a clock window (5–10 min outage per restart); refusing the start's own second too (refuses every dialer for up to 1 s after each start and breaks every real-clock test, the conformance suite included). Recorded in docs/design/server-agent.md; RR34 narrowed to captures sealed in the start's second or by a sender whose clock runs ahead, Ticket → TP-069 (decided)
- 2026-10-31 tests: udp TestANewRouterRefusesWhatWasSealedBeforeIt, TestRestartThenReplayWithinTheWindow; supervisor TestReplaysAfterARestartCostNothing. Mutation: the start check in admitOne disabled (`false &&`) → all three fail; restored. TestConnIDsChangeAcrossTheHour: boundary moved 3 s out, since its dialer 2 s before the hour would seal before the listener's start when run in an hour's last 2 s
- 2026-10-31 docs: udp doc.go (receiver rules, guarantee, Router), router.go, supervisor doc.go, transport Verdict, udp Counters and ipc SharedCounters comments say what the start rule does. This also fixes TP-122's `udp/router.go` bullet
- 2026-10-31 TP-063/TP-070: the rule lives in udp's admit ladder, so it moves with the filter into the gatekeeper (a gatekeeper restart then refuses the same); re-home TestANewRouterRefusesWhatWasSealedBeforeIt and TestReplaysAfterARestartCostNothing there
- 2026-10-31 not verified: a replayed WireGuard initiation across a real supervisor process restart in the lab (the supervisor test drives the shared listener with a fake worker; the datagram never reaches a worker, so no WireGuard device sees it)
- 2026-10-31 make lint, make test green; make lab-test green on 4510855 (LAB_P=1); only this ticket file changes after it
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 5 should-fix)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-069-fix1
