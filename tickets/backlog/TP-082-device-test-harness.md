---
id: TP-082
title: "Device-test harness as a first-class tool"
milestone: M2
area: tooling
repo: thinkpol-vpn
size: L
depends_on: []
refs: []
needs_human: decision
owner: ""
branch: ""
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
- [ ] design doc with a recommendation, approved by the author
- [ ] prototype of the safety core with real (non-stubbed) tests where the OS allows them
- [ ] the in-run self-test catches a broken capture within 10 s

## Notes
Per-round lessons from the kit work: stub-only tests gave false greens; bash `$BASHPID` and `set -u` pitfalls; mixing fixes with new checks in one round; long-lived agent contexts.

## Log
- 2026-10-15 created in backlog (device run 3 and 4 findings)
