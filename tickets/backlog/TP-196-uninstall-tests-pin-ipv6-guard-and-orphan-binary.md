---
id: TP-196
title: "uninstall tests: pin the IPv6 forwarding guard and a binary left without its definition"
milestone: later
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-132]
refs: []
owner: ""
branch: ""
---

## Goal
The tests catch two mutations that pass today: the forwarding guard in uninstall only checks IPv4, and install's refusal to overwrite a binary ignores the case where the binary is on disk without its definition.

## Scope
- `internal/agent/supervisor/leftovers_linux_test.go`, "forwarding it can't turn off": today it refuses only IPv4. Make it a two-case table (refuse IPv4, refuse IPv6). In the IPv6 case, check that accept_ra stays as set. A mutation that builds the "still on" set from family 0 only currently passes; with it, IPv6 forwarding stays on while the isolation tables go.
- `internal/agent/service/install_test.go`: no case has the binary on disk without the definition. Mutation `left != "" && !force` → `defined && !force` (install.go, ~line 280) passes today. Add a case: the definition is removed, ClearHost fails, and the result is an error naming the binary path with the binary kept on disk.

## Out of scope
Code changes in install.go or leftovers_linux.go. The code is correct today; only the tests change.

## Acceptance
- [ ] the IPv6 case of the forwarding guard test fails under the family-0-only mutation
- [ ] the binary-without-definition case fails under the `defined && !force` mutation
- [ ] `make lint`, `make test` pass

## Notes
- From TP-132's delta check, 2026-11-07; the code is correct today, the tests don't pin it.

## Log
- 2026-11-07 created in backlog
