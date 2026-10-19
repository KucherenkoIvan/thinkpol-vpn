---
id: TP-108
title: "Darwin: two dropped errors"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-108-darwin-two-dropped-errors"
---

## Goal
Darwin netcfg and DNS adapters surface read failures instead of treating corrupt or unreadable state as empty or protected.

## Scope
- `internal/dataplane/netcfg/netcfg_darwin.go` (~807): propagate errors from `readRecord` when building `thinkpolRoutes`, so a corrupt owner record does not make that owner's routes look foreign.
- `internal/dataplane/dns/system_darwin.go` (~413, ~419): propagate store errors from `otherResolvers` / `get`, so `Problem()` cannot report protected after a failed read.

## Out of scope
- Linux netcfg or DNS changes.
- Broader netcfg ledger consolidation (TP-102).

## Acceptance
- [ ] fake-based unit tests for both failure paths
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-108-darwin-two-dropped-errors
