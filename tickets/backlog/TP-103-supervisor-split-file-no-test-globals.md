---
id: TP-103
title: "supervisor: split the file, no test globals in production"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: []
owner: ""
branch: ""
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
- [ ] supervisor unit and lab tests pass unchanged or each change explained in the test
- [ ] `make lint`, `make test`, `make lab-test` pass
- [ ] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
