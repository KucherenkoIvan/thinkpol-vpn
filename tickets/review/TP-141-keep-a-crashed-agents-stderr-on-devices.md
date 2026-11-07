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
owner: "agent-tp-141"
branch: "tp-141-keep-a-crashed-agents-stderr-on-devices"
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
- [x] PRD S2, security.md "Node safety" and the service package doc state the device exception
- [x] unit tests: a device definition (launchd plist, systemd unit) names the trace file; a server's names none
- [x] a unit test: a start reads the previous trace, then overwrites the file; the file is 0600 root
- [x] `thinkpol diag` (and status) show the previous run's trace when there is one, and nothing when the last run stopped cleanly
- [ ] device: under the installed service, a crash leaves its trace and the restarted agent shows it (TP-144's run)
- [x] `make lint`, `make test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Agent): done before the M2 lanes start. TP-048's fail-closed-after-crash design rests on the connect-on-boot path, and a crash on it can't be diagnosed today (TP-142).
- **Device evidence (the 2026-10-24 macOS device run, the connect-on-boot reboot).** launchctl showed `runs = 2`, `last exit code = 2`. `up` exits 2 only on a usage error, which the plist's fixed arguments can't cause, so it was almost certainly a Go panic or fatal error. Nothing of it was kept.
- Under KeepAlive launchd restarts the agent within ThrottleInterval (5 s), so the read-then-overwrite order matters: overwrite first and the trace is gone before anyone looks.
- If the agent's log handler also writes to stderr, the file holds the whole run's log, not only the trace. The decision allows the agent's stderr; say in Notes what lands there and whether it needs a size cap.
- TP-133 (`diag` without a running agent) is the other half of crash evidence; the two don't depend on each other.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** The trace file goes in the state or runtime directory (pick one and say why: `/run/thinkpol` doesn't survive a reboot on Linux, and the state directory holds what the node needs, PRD S1). Its `diag` field and its problem code follow the naming rules: snake_case (F5), and the field follows TP-168's JSON convention. F15 (keep, RR40): the S2 amendment says the systemd journal is a separate, known gap.
- **Shape (implementer, 2026-11-07).**
  - *Path:* `crash-trace` in the state directory (`agent.CrashTraceFile`), not the runtime directory: it survives a reboot (a crash just before one is still there; `/run` is a tmpfs on Linux), and it exists before the agent runs, so the manager can open the file before the agent has made any directory of its own (systemd fails a unit whose stderr file it can't open). LoadState counts it as the node's, not an unexpected entry.
  - *Definitions:* a device's plist gets `StandardErrorPath`, its unit `StandardError=append:` (systemd 240+; `truncate:` would empty it before the agent reads it). A server's definition is byte for byte what it was. `service install` picks one by the mode the service will run in (the node file's `mode`, else the node's kind in the map; a node removed from its space is taken for a device). A definition of the other mode isn't "changed by hand". A server's install, and every uninstall, removes the file.
  - *Read, then overwrite:* `up`'s first step, before anything writes to stderr: when fd 2 is that very file (same inode; the path not a symlink), the agent makes it root's 0600 (launchd and systemd create it 0644) and logs what it fixed, reads its head (64 KiB), empties it, and seeks fd 2 to 0. A file it can't fix or empty stops the start. Any other stderr (a terminal, the journal, a server's service) leaves the file alone.
  - *What lands there:* not the log. When stderr is the trace file the agent logs only to its ring, so the file holds what the Go runtime writes (a panic's trace, a fatal error's, SIGQUIT's dump) and the error `up` exits with. A clean stop and a SIGKILL leave nothing. Emptied at each start, it holds one run at most, so the file needs no size cap; memory keeps 64 KiB of its head (`truncated`).
  - *diag:* `last_run` {`unreadable`, `lines`, `truncated`}, line by line, because diag's JSON escapes control characters and a single string would read `\x0a`. Root only, like the host parts (a panic's message or the exit error may name a public address); the group's snapshot has it `unreadable: "root only…"` when there is one. Still schema 1: a field was added.
  - *status:* `last_run_crashed` and a `last run:` text line. No health problem code: health is the node's state now, and a problem would hold "degraded" on a healthy device until its next restart.
- **Device checklist (owner, a later Mac session; TP-144's run).** As root on the Mac, from a build of this branch:
  1. `sudo thinkpol service install`, then `sudo plutil -p /Library/LaunchDaemons/org.thinkpol.agent.plist`. Expect `StandardErrorPath` => `/private/var/lib/thinkpol/crash-trace`.
  2. `sudo launchctl kill QUIT system/org.thinkpol.agent`, wait 10 s. Expect `launchctl print system/org.thinkpol.agent` to show `runs` up by one and `last exit code = 2`.
  3. `thinkpol status`. Expect a `last run:` line.
  4. `sudo thinkpol diag`. Expect `last_run.lines` to start with `"SIGQUIT: quit"`; `thinkpol diag` (not root) shows `last_run.unreadable` "root only…".
  5. `sudo stat -f '%Sp %Su %z' /private/var/lib/thinkpol/crash-trace`. Expect `-rw------- root 0`.
  6. `sudo launchctl kickstart -k system/org.thinkpol.agent` (a clean restart), then `thinkpol status`. Expect no `last run:` line.

- **Round 1 (fix round, 2026-11-07).** What changed from the shape above: install takes a node of unknown kind (removed, or not in the map yet) for a server (`agent.ServiceMode`), with a warning; an agent that runs as a server under a device's definition (at its start, or back in its space) points fd 2 at the null device, removes the file and warns to reinstall, and a server warns of a crash-trace left in its state directory. A device's install creates the file anew, root's 0600 (`agent.CreateCrashTrace`: removed first, O_EXCL|O_NOFOLLOW), before the start, so a trace from before a reinstall is gone; a server's install removes it after the stop. A start reads the head and cuts the file to it, but empties it only once the node has it (`CrashTrace.Release` in `KeepLastRun`): a start failing before keeps the trace and adds its error, bounded by the head plus one run. A file with more than one link isn't read: emptied, removed, stderr to the null device; so is stderr before a fix/cut/empty error is returned, so a restart loop doesn't grow the file. The trace is valid UTF-8, cut at a character. grpc's log goes to the agent's (`localapi.RouteGRPCLog`); under `up -service` a regular-file stderr that isn't the trace gets no log; a stop by a signal returns nil (`agent.CleanStop`). Status has `last_run_unreadable` and its own `last run:` line.

## Review findings
- [x] R1.1 a node of unknown kind gets the device's definition at install; `up` keeps tracing when the node runs (or switches to) server mode: unknown kind → the server's definition; a server under a device's definition stops tracing (fd 2 → /dev/null, file removed, warns to reinstall); tests for both; the state directory doesn't take crash-trace as normal on a server
- [x] R1.2 the manager creates crash-trace 0644, fixed only after start: a device's install creates it root's 0600 (O_CREAT|O_EXCL|O_NOFOLLOW) before starting the service; refuse a link count other than 1; tests
- [x] R1.3 a trace that isn't valid UTF-8 breaks root's Diagnose: cut at a rune boundary, make it valid UTF-8; test 'panic: \xff' through Diagnose and a cut mid-character
- [x] R1.4 the file is emptied at the start of up, the trace kept only at KeepLastRun: a start failing in between loses it; keep it until handed over, bounded; test
- [x] R1.5 nothing tests install's mode choice: test nodeReady for the node file's mode, a server kind, a device kind, a node missing from the map
- [x] R1.6 "nothing after a clean stop" unchecked on the real service: check after the clean restart in lab/service_test.go; a clean SIGTERM stop writes nothing to stderr
- [x] R1.7 grpclog writes to os.Stderr past slog: route it to the agent's logger; a regular-file stderr under `up -service` that isn't the trace sends the log to io.Discard
- [x] R1.8 nits: remove the trace after the old service stops; no line per restart loop when the file can't be fixed; an unreadable trace is its own state in status text; stale docs (agent doc.go, api-overview, api-overview-reference, definition.go); systemd < 240 ignores append:; lab dumps `thinkpol logs` for a device
- [x] R2.1 a server under a device's definition whose start fails before KeepLastRun (Validate, Prepare, a panic) appends each start's error to crash-trace: right after TakeCrashTrace, detach unless the node is a known device (the node file's or flag's mode, else agent.ServiceMode); unit test: a server-mode start failing in Prepare leaves no file
- [x] R2.2 Detach on a device removes the file, so the manager recreates it 0644: on a device recreate it with CreateCrashTrace (a server still removes it)
- [x] R2.3 keepNoTrace removes a server's file without emptying it: truncate before removing
- [x] R2.4 grpcLogger.fatal logs only to the agent's logger: also write the message to os.Stderr before exiting
- [x] R2.5 nothing tests up.go's RouteGRPCLog call or LogOutput's cfg.Service: a test through runUp (or the smallest seam)

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run; owner decision on a device crash trace and PRD S2)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
- 2026-11-07 TP-139 verdicts noted
- 2026-11-07 backlog → in-progress, owner: agent-tp-141
- 2026-11-07 done: a device's definition sends stderr to <state>/crash-trace (plist StandardErrorPath, unit StandardError=append:), a server's unchanged; install picks by mode (Installer.Ready → agent.ResolveMode), removes the file on a server's install and on uninstall; `up` first reads the previous trace (64 KiB head), empties it, makes it root 0600, and logs only to the ring while stderr is the file; diag `last_run` (root only, lines), status `last_run_crashed` + "last run:" line; PRD S2, security.md "Node safety", the agent/service/localapi docs, state.go, api-overview updated
- 2026-11-07 tests: definition_test (device/server plist and unit), definition_darwin_test (plutil reads StandardErrorPath), install_test TestOnlyADevicesDefinitionKeepsACrashTrace + uninstall removes it, crashtrace_unix_test (read-then-empty, append and non-append fd, empty, head limit, other stderr/symlink untouched, lab-only ownership fix), diagnose_test, localapi diagnose_unix_test, state_test; lab TestServiceUnderSystemd: SIGQUIT crash → alice's status line, root's diag "SIGQUIT: quit" first line, alice's diag root only, file 600 root 0 bytes; KILL crash → no crash shown; uninstall removes the file
- 2026-11-07 mutations (all killed): plist/unit stderr dropped, append:→truncate:, server given the trace, server install/uninstall keeping the file, installed() one mode only, no truncate, no seek, no chmod, no same-file check, Stat instead of Lstat, no head limit, read after truncate, group gets the trace, status/proto/text field dropped, crash-trace counted unexpected; in the lab: no chown (TestTheTraceIsMadeRoots), log still to stderr in up.go (TestServiceUnderSystemd fails at service_test.go:181)
- 2026-11-07 ran: make lint, make test green; make lab-gotest PKG=./internal/agent/ (root) green; full make lab-test green on 86c829e (merge of origin/rewrite)
- 2026-11-07 not verified: launchd on a Mac (device box open; checklist in Notes, the owner's later session/TP-144)
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-07 round 1 fixed: R1.1 agent.ServiceMode (unknown kind → server, warned), Node.KeepLastRun/keepNoTrace detach a server's stderr (start and back in space), leftover warned; R1.2 agent.CreateCrashTrace at a device's install before the start, link count ≠ 1 refused; R1.3 head cut at a rune, ToValidUTF8; R1.4 emptied only at CrashTrace.Release after KeepLastRun, file cut to its head at the start; R1.5 TestServiceModeIsTheNodesMode over real state directories; R1.6 lab: clean restart and reboot show no last run, runUp returns nil on cancellation; R1.7 RouteGRPCLog, CrashTrace.LogOutput; R1.8 removal after the stop, stderr detached before a fix/empty error, last_run_unreadable status field and line, docs (agent/service/localapi doc.go, definition.go, state.go, api-overview, api-overview-reference, systemd < 240 note), lab dumps thinkpol logs
- 2026-11-07 tests added: TestAFailedStartKeepsTheTrace, TestTheTraceIsUTF8, TestAHardLinkedTraceIsRefused, TestCreateCrashTraceReplacesWhatWasThere, TestTheLogStaysOffTheDisk, TestACleanStopIsNoError, TestAServerKeepsNoTrace (server, device, back as a server, a file left), TestServiceModeIsTheNodesMode, localapi TestATraceOfAnyBytesIsServed and TestGRPCLogsToTheAgentsLog; changed: TestAStartReadsThePreviousTraceThenOverwritesIt (release step), TestALongTraceKeepsItsHead (file cut), TestThePreviousRunsTraceShows (unreadable), TestOnlyADevicesDefinitionKeepsACrashTrace (planted file replaced by 0600 before the start, crash on stop, unknown kind)
- 2026-11-07 mutations (all killed): unknown kind → device; server keeps tracing at start; no detach on the switch back; no dup2; detach keeps the file; no link check; create 0644; create without remove/O_EXCL (follows the symlink); install doesn't create; removal before the stop; no unknown-kind warning; no ToValidUTF8 (unit and through Diagnose); no rune cut; take empties; no cut to head; seek current instead of end; release doesn't truncate; CleanStop passes through; log to any regular file; no unreadable status; no unreadable line; unreadable counts as a crash; grpclog not routed; server leftover not warned
- 2026-11-07 ran: make lint, make test green; make lab-gotest PKG=./internal/agent/ ./internal/agent/service/ ./internal/agent/localapi/ (root) green (it caught an inode-reuse assumption in the install test, fixed); full make lab-test green on 797e52c (merge of origin/rewrite)
- 2026-11-07 not verified: launchd on a Mac (device box open; checklist in Notes); systemd < 240 not run
- 2026-11-07 has-errors → review
- 2026-11-07 review → has-errors (round 2 findings R2.x)
- 2026-11-07 round 2 fixed: R2.1 up reads its config right after TakeCrashTrace (upConfig) and calls CrashTrace.KeepOnlyOnADevice: kept only when the mode (env, flag, node file) is device, or auto and ServiceMode says a known device; otherwise detached before Prepare (a config that wasn't read is judged by the trace's directory); R2.2 Detach on a known device makes the file anew (CreateCrashTrace), a server's still removes it; R2.3 a server's detach (keepNoTrace, KeepOnlyOnADevice, Take's failures) empties the file before removing it; R2.4 grpcLogger.fatal also writes to os.Stderr; R2.5 tests through runUp (crashTracePath seam); agent doc.go and api-overview updated
- 2026-11-07 trade-off: a device on auto whose map or node file can't be read is no longer known to be a device, so its failed start detaches and the previous trace is gone (R2.1 as specified); a device by its mode keeps it
- 2026-11-07 tests added: cmd/thinkpol TestOnlyAKnownDevicesFailedStartKeepsTheTrace (server by flag, by node file, unknown kind: file gone after a Prepare failure; device by flag, by node file: trace kept), TestUpRoutesItsLog (grpc's log reaches the agent's; a regular-file stderr gets the log without -service, nothing under it); agent TestOnlyAKnownDeviceKeepsTracing, TestADeviceDetachedMakesTheFileAnew, TestAServersTraceIsEmptiedBeforeItIsRemoved (skipped as root); localapi TestGRPCFatalWritesToStderr (subprocess)
- 2026-11-07 mutations (all killed): KeepOnlyOnADevice call dropped from up.go; unknown kind taken for a device; a device's detach removes instead of recreating; a server's detach not emptied; grpc fatal not written to stderr; RouteGRPCLog call dropped; LogOutput passed false for cfg.Service
- 2026-11-07 ran: make lint, make test green; make lab-gotest PKG=./internal/agent/ ./internal/agent/service/ ./internal/agent/localapi/ ./cmd/thinkpol/ (root) green on 6f96d6a; full make lab-test not run this round (brief: the last full lab passed on 797e52c, the change is local to start-up and covered by unit tests)
- 2026-11-07 not verified: launchd on a Mac (device box open; checklist in Notes); systemd < 240 not run; full lab on this round's commit
- 2026-11-07 has-errors → review
