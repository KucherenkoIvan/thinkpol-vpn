---
id: TP-122
title: "Code comments that contradict the code"
milestone: M2
area: docs
repo: thinkpol-vpn
size: S
depends_on: [TP-077]
refs: []
owner: ""
branch: ""
---

## Goal
No code comment states something the code doesn't do.

## Scope
Found while TP-077 checked the moved mechanism against the code. Fix each comment to say what the code does (or, where the comment is the intent and the code is wrong, say so in the Log and leave the code to a ticket):
- `netcfg/netcfg_other.go` (~11) and `dns/system_other.go` still say "(macOS: TP-019)"; macOS has its own files now.
- `agent/config.go` (~43) says logs go to "stderr only"; they also go to the in-memory ring (`logring`).
- `udp/router.go` (~24-27) says a worker still drops replays after a supervisor restart; it doesn't (TP-069), and it gives a replay window after a restart of up to 10 minutes where TP-069 says 5. Say what holds and point to the residual-risks row.
- `supervisor/options.go` (~154-156) overstates what a worker keeps when its cgroup is missing: only the process-count cap (RLIMIT_NPROC) is left.
- Grep for other "TP-0xx" mentions in comments that name a ticket as still to come when it is done.

## Acceptance
- [ ] each comment above says what the code does
- [ ] `make lint`, `make test` pass

## Notes
- From TP-077's Log (2026-10-22).

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
