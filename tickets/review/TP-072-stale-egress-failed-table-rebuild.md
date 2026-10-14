---
id: TP-072
title: "Stale egress after a failed table rebuild"
milestone: M2
area: agent/supervisor
repo: thinkpol-vpn
size: S
depends_on: []
refs: [R1, DESIGN#ipv6]
owner: agent-composer
branch: tp-072-stale-egress
---

## Goal
A transient `applyTables` failure does not leave an existing space on stale egress with no retry path.

## Scope
- `supervisor_linux.go:229-253`: `SetSpaces` updates existing workers' egress and config before `applyTables`; on failure `rollback` undoes only new workers, and the next `SetSpaces` computes `before` from already-updated memory so `before == after` and `egressChanged` never fires. Same shape at `uplinkMoved` (`:404-410`).
- `supervisor_linux.go:560-565`: `Close` removes the isolation tables before restoring forwarding — a brief window where the root forwards everything with no tables.

## Out of scope
- Rollback semantics for brand-new workers only (TP-009 R2.3).

## Acceptance
- [x] after `applyTables` fails with existing spaces, a later `SetSpaces` still applies egress changes — `TestSetSpacesRetriesEgressAfterIsolationFailure` (lab)
- [x] a test: `applyTables` fails with existing spaces (egress retry or ordering fix as implemented) — same test plus `TestCloseTeardownOrder` (lab)

## Notes
- **Independent review (2026-10-15):** fails closed, not an isolation hole; a node that hits one transient nftables error keeps the old egress until a worker restart.
- SetSpaces snapshots existing workers and `restoreWorkers` on `applyTables` failure; `uplinkMoved` restores the previous uplink on failure; Close calls `forwarding.restore` before `removeIsolation`.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-072-stale-egress
- 2026-10-15 in-progress → review — restore worker/uplink state on failed rebuild, Close forwarding-first; make lint, make test, lab-gotest supervisor pass
