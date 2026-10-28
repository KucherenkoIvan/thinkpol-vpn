---
id: TP-141
title: "Keep a crashed agent's stderr on devices"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
needs_human: macos
depends_on: []
refs: [S2, docs/design/security.md#node-safety]
owner: ""
branch: ""
---

## Goal
When a device's agent dies under the service (a panic, a runtime fatal error), its stderr survives in one root-only file, and the next start shows it through `thinkpol diag` and status. Today a device crash leaves nothing: the launchd definition sets no `StandardErrorPath`, and the log ring dies with the process.

## Scope
- **Decided (owner, 2026-10-24):** a crash trace is allowed on **devices only**: one root-only (0600) file in the service's state directory, overwritten on each start, holding the agent's stderr and panic trace. Servers and entry nodes keep no disk logs.
- The service definition (`internal/agent/service/definition.go` ~75–77, and the systemd unit beside it) sends a device agent's stderr to that file. A server's definition is unchanged.
- The file is 0600 root whatever the OS creates it with (launchd and systemd don't promise a mode); a start that finds it wider fixes it or refuses, and says so.
- The file is overwritten on each start, so a start must read the previous run's trace before it overwrites it: the agent keeps it in memory and `thinkpol diag` (and status, as a short "the last run crashed" line or problem) shows it. Decide the exact shape in Notes; the diag schema version stays 1 if only a field is added.
- **PRD S2 is amended** in this branch to say so: no logs on disk, except a device's crash trace (one file, root only, overwritten on each start). docs/design/security.md "Node safety", the `service` package doc (`internal/agent/service/doc.go` ~110) and the definition's comment say the same.

## Out of scope
- Server and entry nodes: no change, and no file.
- Finding the boot crash itself: TP-142.
- Keeping more than the last run, or shipping traces anywhere.

## Acceptance
- [ ] PRD S2, security.md "Node safety" and the service package doc state the device exception
- [ ] unit tests: a device definition (launchd plist, systemd unit) names the trace file; a server's names none
- [ ] a unit test: a start reads the previous trace, then overwrites the file; the file is 0600 root
- [ ] `thinkpol diag` (and status) show the previous run's trace when there is one, and nothing when the last run stopped cleanly
- [ ] device: under the installed service, a crash leaves its trace and the restarted agent shows it (TP-144's run)
- [ ] `make lint`, `make test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Agent): done before the M2 lanes start. TP-048's fail-closed-after-crash design rests on the connect-on-boot path, and a crash on it can't be diagnosed today (TP-142).
- **Device evidence (the 2026-10-24 macOS device run, the connect-on-boot reboot).** launchctl showed `runs = 2`, `last exit code = 2`. `up` exits 2 only on a usage error, which the plist's fixed arguments can't cause, so it was almost certainly a Go panic or fatal error. Nothing of it was kept.
- Under KeepAlive launchd restarts the agent within ThrottleInterval (5 s), so the read-then-overwrite order matters: overwrite first and the trace is gone before anyone looks.
- If the agent's log handler also writes to stderr, the file holds the whole run's log, not only the trace. The decision allows the agent's stderr; say in Notes what lands there and whether it needs a size cap.
- TP-133 (`diag` without a running agent) is the other half of crash evidence; the two don't depend on each other.

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run; owner decision on a device crash trace and PRD S2)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
