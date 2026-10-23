---
id: TP-082
title: "Device-test harness as a first-class tool"
milestone: M2
area: tooling
repo: thinkpol-vpn
size: L
depends_on: []
refs: []
needs_human: macos
owner: "agent-tp-082"
branch: "tp-082-device-harness"
---

## Goal
Decide and prototype how to make the device harness a maintainable tool: a small frozen safety core separate from checks that change often, check logic out of bash, and an in-run self-test that validates harness machinery in the first seconds of a run.

## Scope
Real-device testing has found every macOS bug the lab could not: mDNSResponder scoping, the own-IPv6 checksum, the link-liveness issue. Today the harness lives outside this repo as a large private bash kit. It runs as the developer, takes sudo for route/scutil/tcpdump, restores the machine (a dead-man timer, record-based rollback), drives a remote exit container, captures leaks and samples resources. It has grown into a second product, and its bugs cost whole device cycles. Examples: a guard bug voided every leak capture in one run; a truncated-file bug made valid captures read as invalid. Its tests rely on stubs that cannot reproduce root, routing or setuid behaviour.

R&D deliverables:
- a short design doc comparing the options (Go tool in this repo / Python / keep bash), with a recommendation
- what stays private: anything naming real servers stays outside the public repo, provided through config
- a prototype of the safety core and one check
- a migration plan

## Out of scope
Rewriting every check in this ticket.

## Acceptance
- [x] design doc with a recommendation, approved by the author
- [x] prototype of the safety core with real (non-stubbed) tests where the OS allows them
- [x] the in-run self-test catches a broken capture within 10 s

## Notes
Per-round lessons from the kit work: stub-only tests gave false greens; bash `$BASHPID` and `set -u` pitfalls; mixing fixes with new checks in one round; long-lived agent contexts.
- Kit bugs found by cross-model analysis of device run 4 (examples of why the harness needs real tests):
  - pcaps were decoded to empty text (stderr dropped), so packet-count checks always saw zero and could never fail. The run-4 conclusions were confirmed only by re-reading the pcaps by hand.
  - log-line counts double-counted a file that is a prefix of another
  - a counter diff subtracted unrelated lines (the N12 checksum figure)
  - the route monitor missed events during a 12k-route burst

### Prototype (2026-10-23)
- The design is approved and stays private; its public parts are in `lab/devicetest/doc.go` (what a run guarantees, how a plan is written), `lab/devicetest/safety/doc.go` (the frozen core, the freeze rule, what is tested where) and `docs/design/lab.md` "Device testing". The migration plan is the private design's section 9: the old kit runs the phase-end run, then the exit driver, then one plan per M2 ticket.
- Built, in the owner's prototype scope (answer 13): the safety core (`lab/devicetest/safety`, pinned by `FROZEN` and `TestTheSafetyCoreIsFrozen`), the capture self-test (`lab/devicetest/selftest.go`), the evidence folder (`lab/devicetest/evidence`), and TP-096's plan (`lab/devicetest/plans/tp096.go`). Product readers reused, not copied: firewall's pfctl readers (now exported), `trusteddir` (a new `OpenOwnedBy` for root writing the owner's evidence) and its boot session, netcfg's `DefaultInterface`, ifbind, and the lab's pcap reader (moved to `lab/pcap`). netcfg's route-record reader isn't needed: route rollback becomes `thinkpol rollback` (TP-134).
- Acceptance evidence: the safety core's tests run as the user on the Mac (`make test`: kill -9 of a journaling child, a cut journal line, a power loss as another boot session, the dead-man against a killed helper, a stop file, no heartbeat, a fresh one and a stale one, the helper's restore on input end and after SIGINT/SIGHUP, an unfinished run blocking the next, symlinks against the evidence writer, the root-read allowlist, the live reader and the decode check on a capture recorded in a lab node) and as root in lab nodes (`make lab-test`: the launch script's root copy and its hash check, a real tcpdump applied and undone through the journal, a whole run through the launch script, helper, dead-man and tcpdump, and a broken capture caught in 4.7 s with nothing of the plan's run).
- Size: about 4.5k lines under `lab/devicetest` with comments and package docs, plus 1.8k lines of tests (the design estimated 1.6k and 1.1k for the prototype). TP-096's plan is 42 lines.

### Device checklist (the owner's first run, answer 14)
From a checkout of this branch (or `rewrite` once merged), as yourself, no VPN or thinkpol agent running, Wi-Fi on:
1. Build: `go build -o /tmp/devicetest ./lab/devicetest`. Then `/tmp/devicetest plans TP-096`: expect 2 steps, 9 root reads, one change ("load pf's main ruleset: "set skip on lo", then /etc/pf.conf") with its undo, and a capture on your physical interface. Nothing is asked and nothing runs as root.
2. `/tmp/devicetest selftest`, type `yes`, then your sudo password. Expect `self-test ok in …` (under 10 s), then a last line `devicetest selftest recorded: 0 of 0 steps, selftest ok, restore CLEAN -> …/thinkpol-evidence/<date>-selftest`. If it says SELF-TEST FAILED, go on to step 6 and send the folder: that is what the self-test is for.
3. `/tmp/devicetest run TP-096`, `yes`, password. Expect `recorded: 2 of 2 steps, selftest ok, restore CLEAN`. If a `STOP:` line asks what to do, press Enter (it restores and ends). If the restore says `REBOOT` or `LEFT`, do what each item's `next` says (for pf: one `sudo pfctl -f /etc/pf.conf`; never `pfctl -F` or `pfctl -d`), and reboot if pf still differs.
4. Ctrl-C: run `/tmp/devicetest run TP-096` again, `yes`, password, and press Ctrl-C twice as soon as `step 1 stock` appears. Expect `stopping after the operation running now, then restoring`, then `restoring, wait`, and `restore CLEAN`.
5. A closed terminal: in a new window run `/tmp/devicetest selftest`, `yes`, password, and close the window at once. In another window, after 10 s: `/tmp/devicetest restore` (it asks for sudo). Expect a result with `"verdict": "CLEAN"` (`no unfinished run` if the helper had already restored by itself).
6. Afterwards: `sudo ls /private/var/db/thinkpol-devicetest` lists `run-…` directories and no `active`; `ls -d /private/tmp/tpdt.*` finds nothing. Zip each `~/thinkpol-evidence/<date>-…` folder of the session and send the paths. An agent judges them; no PASS or FAIL comes from the tool.

What the judge reads: `selftest/selftest.json` and the decode beside it; `steps/02-skip-on-lo/cmd-002…Interfaces-v.out` (`lo (skip)`, or `lo0 (skip)` instead); `actions/pf-main-*` (the stock-rules parse, the load and the reloads); `restore/result-*.json`; `snapshots/00-baseline` against `99-after-restore`.

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
- 2026-10-15 docs: kit bugs found in device run 4 analysis
- 2026-10-23 design reviewed and approved by the owner (orchestrator's draft, kept private while it names the owner's setup). Stack: Go, in `lab/devicetest`. Answers to the 14 questions are recorded in the design's decision log. Prototype scope: the safety core, the capture self-test, the evidence folder (`~/thinkpol-evidence/<date>-<ticket>/`, captures kept privately), and TP-096's pfctl plan. Changing the safety core takes its own ticket and the owner's approval. Reboot tests use a printed recovery sheet. Follow-ups: TP-133 (diag without an agent) and TP-134 (`thinkpol rollback`)
- 2026-10-23 backlog → in-progress — owner: agent-tp-082, branch: tp-082-device-harness
- 2026-10-23 prototype (0e513c5): the safety core `lab/devicetest/safety` (journal, typed actions, root copy and helper, dead-man, baseline and restore with the runbook's pfcheck, pfrestore, waitstop and waitrel; pinned by FROZEN), the capture self-test, the evidence folder, plans as data with depguard (no safety, no os/exec) and TP-096's plan; the lab's pcap reader moved to `lab/pcap`; `trusteddir.OpenOwnedBy`; firewall exports its listing readers; docs in both doc.go files, `docs/design/lab.md`, DESIGN.md and the lab README; TP-096's ticket says its plan runs through the tool
- 2026-10-23 mutations, each caught by its test: Do without the dead-man check, a cut journal line as an error, volatile changes of another boot undone, the dead-man blind to a gone helper, blind to the heartbeat, a zombie counted alive, the helper keeping SIGINT/SIGHUP, evidence directories followed through symlinks, any pfctl arguments allowed, markers not noted, the decode check without the positive, no negative control in the filter, pf leftovers never REBOOT, lo0 skips ignored, evidence allowed in a git checkout, a private config readable by others, the listing without the undo, root's own directory taken as the evidence folder, Pre ignored, a new run despite an unfinished one, the restore without the baseline compare, a plan importing os/exec or the core (depguard); in the lab: the launch script without its hash check, the self-test ignoring an unseen marker
- 2026-10-23 not verified (Mac only, in the device checklist): sudo and the root copy under /private/tmp with shasum; Apple's tcpdump stream on en0 and a broadcast marker bound with IP_BOUND_IF; the pf action against a real pfctl (its precondition assumes `pfctl -n -v -f /etc/pf.conf` prints rules as `-s rules` does, and refuses otherwise); whether loading /etc/pf.conf clears the skip flag; the macOS normalisers on real listings (tested on recorded shapes); Ctrl-C and a closed terminal under sudo; waitstop, waitrel and `pfctl -e` (no plan runs an agent yet); Go's monotonic clock across a sleep (no sleep step)
- 2026-10-23 needs_human: decision → macos (the design is decided; the owner runs the device checklist in Notes, and an agent judges its evidence)
- 2026-10-23 lab: `make lab-test` (LAB_P=4) green on bebc261
- 2026-10-23 in-progress → review
