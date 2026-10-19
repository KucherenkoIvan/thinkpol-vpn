---
id: TP-103
title: "supervisor: split the file, no test globals in production"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: []
owner: agent-glm
branch: tp-103-supervisor-split-file-no-test-globals
---

## Goal
The Linux supervisor is several focused files with test-only hooks behind options, not package globals in the production build.

## Scope
- Split `internal/agent/supervisor/supervisor_linux.go` along its natural seams (state machine ~48–644, worker record ~646–778, process lifecycle ~780–1199); shorten `run` (~814–1028) and isolate `applyIsolation` (`isolation_linux.go` ~199–353).
- Move test-only package state out of production builds: `failApplyIsolation`, `unboundAccepts` (`isolation_linux.go` ~105, ~110), `writeSysctl`, `procSys` (`forwarding.go` ~18, ~284); sysctls behind an interface on `Options`, fault injection via an unexported hook option.
- Untangle `shared.go` listener lifecycle from the reply-window tracker.
- If TP-102 has already landed, add a `funlen` gate at about 80 lines to `.golangci.yml`; otherwise the sibling ticket owns that gate.

## Out of scope
- Changing isolation semantics or worker sandboxing rules.
- `cgroup_linux.go` rmdir retry behaviour unless a test needs it.

## Acceptance
- [x] supervisor unit and lab tests pass unchanged or each change explained in the test — no assertion changed; the tests' hook plumbing moved to the Options fields (forwarding_test.go fake, rollback_linux_test.go failRebuilds, egress_linux_test.go WithUnboundAccepts), each noted in its diff; isolation_golden_linux_test.go added
- [x] `make lint`, `make test`, `make lab-test` pass — lint clean on every OS, test ok, lab-test ok 34 packages @ dcb2679 (finished 2026-10-19 18:22; two earlier runs failed on OOM and timeouts while 19 other tplab containers were running, green on rerun)
- [x] no behaviour change: existing tests pass unchanged, or each changed test says why — the golden lab test pins the nftables rules byte-identical across the rule-builder refactor (goldens generated from the pre-refactor code at c171664)

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-103-supervisor-split-file-no-test-globals
- 2026-10-19 in-progress → review — file split (supervisor_linux.go keeps the state machine; worker_linux.go, process_linux.go new); run split into startWorker, markStarted and a session (awaitReady, serve); applyIsolation's rule DSL one method per chain; shared.go split (replies.go); test-only globals moved behind Options (sysctls interface, failIsolation, unboundAccepts hooks); cgroup rmdir retries back off 2 ms (on the task prompt's order, though the ticket's out-of-scope lists it); funlen gate skipped: TP-102 is still in backlog, its ticket owns the gate
