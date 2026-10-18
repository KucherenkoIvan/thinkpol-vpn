---
id: TP-106
title: "Remove dead code"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
owner: ""
branch: ""
---

## Goal
Unused types and packages are removed so exports and go.mod pins reflect real imports only.

## Scope
- Delete `internal/dataplane/telemetry` if nothing imports it (verify before removal).
- Remove `transport.SendReporter` if no consumer uses it beyond compile-time asserts in `udp/transport.go` (~43–44); keep shaping behaviour tests intact.
- Move `transport.Buckets` (`shaping.go` ~307–318), a panicking test helper exported from the port, into a test file or `transporttest` as appropriate.
- Delete `internal/shared/kernel.go` after confirming go-kernel stays in `go.mod` through real imports (agent and other packages already import it).

## Out of scope
- Telemetry product feature (TP-041).
- Refactors that only rename without deleting dead symbols.

## Acceptance
- [ ] `go mod tidy` leaves go-kernel required; no broken imports
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
