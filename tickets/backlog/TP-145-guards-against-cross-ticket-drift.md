---
id: TP-145
title: "Guards against cross-ticket drift: env reads and the Engine's size"
milestone: M2
area: repo
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/control-plane.md#kernel-usage]
owner: ""
branch: ""
---

## Goal
Two things a review fixed and a later ticket undid can't come back unnoticed: environment reads inside `internal/`, and the dataplane Engine growing field by field. A lint rule or a test fails instead.

## Scope
- **Env reads.** A lint rule (forbidigo or similar) bans `os.Getenv` and `os.LookupEnv` in `internal/`, non-test files. Move the existing reads to the composition root (`cmd/thinkpol`) or go-kernel config:
  - `internal/agent/config.go:128,131` (`ApplyOSDefaults`: `THINKPOL_STATE_DIR`, `THINKPOL_API_SOCKET`);
  - `internal/agent/service/host.go:64` (`SUDO_USER`, TP-046);
  - `internal/dataplane/dns/inspect_linux.go:50` (`DBUS_SYSTEM_BUS_ADDRESS`, TP-091).
- **The Engine.** `Engine` in `internal/dataplane/engine.go` has 47 field declarations (46 at M1). Add a budget, or a test that fails when the count grows, with a message that says to move a block out rather than raise the number. Remove its "Tests swap them" hooks (`assign`, `rules`, engine.go ~128) where a test can use a port instead; say in Notes which stay and why.

## Out of scope
- Slimming the Engine below today's count: a refactor of its own, if wanted.
- Tests: they may keep reading `THINKPOL_LAB` and the like (AGENTS.md).

## Acceptance
- [ ] the lint rule fails on an `os.Getenv` or `os.LookupEnv` in a non-test file under `internal/` (shown once, then removed)
- [ ] no such read is left under `internal/`; the defaults are applied in `cmd/thinkpol` or through go-kernel config
- [ ] a check fails when `Engine` gains a field
- [ ] `make lint`, `make test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Hygiene): done before the M2 lanes start, since every lane lands in the agent and the Engine.
- TP-105 (`e1d96fb`) moved the env reads to `cmd/thinkpol/up.go`; TP-075 round 3 (`da8b8a8`) moved them back the same day, and two more reads came in with TP-046 and TP-091. Reviews didn't check earlier tickets' acceptance against later merges.
- `.golangci.yml` already runs forbidigo, but only for `internal/dataplane/path` (an exclusion `path-except: internal/dataplane/path/` turns it off elsewhere). The new rule needs its own scoping, or depguard-style rules per path, without loosening the path layer's.
- From the 2026-10-24 code-health review (the Engine finding was "partly fixed": `deviceSet` and `osRoutes` were added beside the old fields, and the struct never shrank).

## Log
- 2026-10-24 created in backlog (2026-10-24 code-health review: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Hygiene)
