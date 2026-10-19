---
id: TP-106
title: "Remove dead code"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-106-remove-dead-code"
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
- [x] `go mod tidy` leaves go-kernel required; no broken imports — `go mod tidy` changed nothing (de8ec10); go-kernel v0.20.0 still required through real imports in `internal/agent` (app, config, grpckit, observability, ddd) and `cmd/thinkpol`
- [x] `make lint`, `make test`, `make lab-test` pass — lint and test green at de8ec10; full lab run green at de8ec10, 34 packages, `LAB_P=1` (two other wave-0 tickets share Docker)

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-106-remove-dead-code
- 2026-10-19 in-progress → review — telemetry had only a doc.go and no importers; SendReporter had no consumer beyond udp's compile-time asserts (its `Sent` methods stay, tests call them on concrete types); Buckets had no non-test callers, moved to transporttest; kernel.go deleted, go-kernel pinned by real imports. make lint, make test and a full make lab-test (LAB_P=1, 34 packages) green at de8ec10. Nothing unverified: no device-only or platform-specific behaviour touched.
- 2026-10-19 review round 1: all three reviewers: merge; the orchestrator applied their doc items: Buckets is for tests (it imports testing), transporttest's package doc names it, DESIGN keeps telemetry/ as planned for TP-041; make lint, make test green
