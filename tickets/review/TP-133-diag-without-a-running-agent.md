---
id: TP-133
title: "`thinkpol diag` as root without a running agent"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-091]
refs: [docs/design/desktop-client.md#the-local-api]
needs_human: macos
owner: "agent-tp-133"
branch: "tp-133-diag-without-a-running-agent"
---

## Goal
After a crash (kill -9, power loss) `thinkpol diag` still records what the dead agent left on the host: the evidence a device run needs most is the state after a crash, and today `diag` needs a running agent to answer.

## Scope
- When the local API doesn't answer, root's `diag` reads the host itself with the same readers the agent uses (netcfg, firewall, dns: routes and records, the guard's table/anchor and pf reference, the resolvers) and writes the same versioned snapshot, with `agent: "not running"` and the agent-only parts (status, TUN, last Apply) unreadable with that reason.
- Read-only, exactly as the agent's readers are: no lock taken, no directory made. A non-root caller without an agent gets an error, not a partial snapshot.
- The schema version stays 1 if only a value is added; say so.

## Acceptance
- [x] lab: SIGKILL a connected device's agent, then `diag -o` as root records its leftover routes, guard and resolver configuration, matching `ip -j`, `nft -j` and resolvectl
- [x] a unit test: no agent and no root → an error
- [ ] macOS: with no agent, root's diag records the guard's and kill switch's pf anchors and references, routes and the resolver configuration, through the agent's own read-only readers; unit tests with fakes; checked for real in the M2 device run (S5)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Owner's answer to the device-harness questions (2026-10-23, TP-082 question 2). The harness's crash steps use it.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Agent lane: after TP-141, before TP-140. Starts only after the owner's TP-139 session, whose verdicts on its planned surface go into this ticket first.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** Overlaps TP-168 (`status` local, `diag` over the network, one JSON convention): the new `agent` field follows that convention (snake_case, every field, `schema_version`), and its values are snake_case. Exit codes follow sysexits (TP-167): the fallback's code is decided against that table, and non-root is 77. Whichever of TP-133 and TP-168 starts second merges the other first.

- **As built (2026-11-15).** Schema stays 2, not 1: TP-168 had already bumped it to 2 (enum spelling); TP-133 only adds fields, `agent` (`running`, `not_running`, `not_answering`) and `status_unreadable` (`status` is null without the agent). The fallback is automatic. Exit codes against TP-167's table: no agent running (nothing accepts the socket: none, or a SIGKILLed agent's stale one) → the snapshot, 0, since it is all there is to take; an agent that holds the socket but gives no snapshot within a minute (or drops the connection unanswered) → the snapshot is written all the same and diag exits 69 (EX_UNAVAILABLE, `service_not_answering`, a new client-side refusal): the evidence is kept, but the result is short of the agent's snapshot, and "anything short of the requested state is not 0"; anyone but root → 77 and no snapshot, in both cases. Offline, `last_run` is read from the crash trace file as it is (never fixed, cut or emptied as a start does), and `agent_version`/`os` are the CLI's. macOS refuses a full socket backlog as it refuses a dead agent's socket, so a hung agent there with every slot taken reads as `not_running`.
- **Device checklist (M2 device run, S5), for the macOS box.** With the kill switch on, then off: SIGKILL the agent (`sudo launchctl kill SIGKILL system/<label>` or `sudo kill -9 <pid>`, restart held off), then `sudo thinkpol diag -o /tmp/diag-dead.json; echo $?`. Expect exit 0, `"agent": "not_running"`, `status` null; `guard` and `kill_switch` (the latter only with the switch on) present with their pf anchors' rules, `pf.enabled`, and `pf.reference` recorded with the dead agent's pid; `routes` the dead agent's; `dns` matching `scutil --dns`. Compare with `sudo pfctl -a com.apple/000.thinkpol -sr`, `sudo pfctl -a com.apple/001.thinkpol-killswitch -sr`, `sudo pfctl -s References`, `netstat -rn`. Then `thinkpol diag` as the member: exit 77, nothing on stdout. Then `sudo thinkpol rollback` and diag again: guard and kill switch gone.

## Log
- 2026-10-23 created in backlog (TP-082 design answers)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
- 2026-11-07 TP-139 verdicts noted
- 2026-11-07 milestone → later (owner's MVP cut: diag without an agent: no done-when needs it)
- 2026-11-15 milestone later → M2 (owner, device-run plan answer 6b: the crash session's evidence comes from diag)
- 2026-11-15 backlog → in-progress, owner: agent-tp-133
- 2026-11-15 built: localapi.DiagnoseOrReadHost (the fallback, its exit cases), agent.DiagnoseHost (root's check, the agent's Inspector, the crash trace read as it is), Diagnostics.agent and status_unreadable (schema 2), service_not_answering → 69; darwin pf readers given injectable entries (inspectIPv6Guard, inspectKillSwitch); docs: localapi doc.go, api-overview(-reference).md, desktop-client.md
- 2026-11-15 tests: agent TestTheHostIsReadWithoutTheAgent, TestTheTraceFileIsOnlyRead, TestTheHostsSnapshotIsRoots (no agent and no root → ErrDiagNeedsRoot, nothing read); localapi TestDiagWithoutAnAgentReadsTheHost, TestARunningAgentTakesTheSnapshot, TestAnAgentThatDoesntAnswerStillLeavesTheHostsSnapshot, TestNoSnapshotWhenTheHostCantBeRead, TestARefusalOrTheCallersCancelReadsNoHost, TestDialTimedOut; cmd TestDiagWithoutAnAgentExitsBySysexits and the sysexits table's diag rows (not root → 77, root → 0); darwin firewall TestADeadAgentsGuardAndKillSwitchAreReadWithoutIt (fake pf); lab TestDiagShowsWhatTheHostHolds's "after a SIGKILL" step
- 2026-11-15 mutations, each killed: M1 offline snapshot skips the kill switch; M2 trace read ignores its link count; M3 DiagnoseHost without its root check; M4 status sent though unreadable; M5 server doesn't say running; M6 only a deadline counts as silence; M7 not answering returns no error; M8 the caller's cancel reads the host; M9 a dial timeout isn't silence; M10 the host reader's refusal dropped; M11 not answering exits 1; M12 diag reads no host without the agent; M13 the kill switch's reader takes the guard's record; M14 the guard's reader looks in another directory; lab: offline snapshot drops the routes (the SIGKILL step fails); an explicit EAGAIN check survived (Errno.Timeout already counts it) and was removed
- 2026-11-15 runs: make lint and make test green on 931498e (merge of rewrite); lab-gotest TestDiagShowsWhatTheHostHolds green on e90d069; full make lab-test green on 931498e; darwin firewall/netcfg/dns and localapi, cmd/thinkpol green on a Mac; no known flake seen
- 2026-11-15 not verified: macOS for real (the macOS box stays open for the M2 device run, S5, checklist in Notes); a hung agent filling the socket backlog (Linux EAGAIN) only by a synthetic error; the not_answering path's lab run (unit-tested with silent listeners)
- 2026-11-15 in-progress → review
