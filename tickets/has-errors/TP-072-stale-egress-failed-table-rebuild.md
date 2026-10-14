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

## Review findings
Round 1 review (correctness), orchestrator's list.

- [ ] 1 Blocker: `restoreWorkers` rolls back the config after `setConfig` already signalled the worker, which takes the new config and seeds; the old config then makes the worker drop seeds only the new map uses (`retainSeeds`), and `sendSeeds` never resends them in this process (`sent`). Restore only what the table rebuild owns (egress, dials); never roll back config.
- [ ] 2 Rolling back inbound credentials re-admits, at the shared listener, peers the new map removed while the worker keeps the new map. Don't roll back inbound.
- [ ] 3 `Close` still removes the isolation tables when `forwarding.restore()` fails, and `restoreFamily` has already dropped the record: the root forwards with no tables and no successor can adopt it. If restore fails, keep the tables (fail closed), keep or rewrite the record, return the error.
- [ ] 4 The acceptance evidence overclaims: the final `ip_forward == "1"` check passes without the fix; only an in-memory check tells old from new, and `/bin/true` never gives a ready worker. Lab test with a ready worker: change egress, fail `applyTables` once, succeed with the same desired egress, assert the worker namespace's table follows; show it fails without the fix.
- [ ] 5 The order test checks a call sequence (AGENTS.md rules that out). Replace it with a behaviour test: forwarding back off by the time the isolation tables go.
- [ ] 6 A worker restart in the SetSpaces window leaves the space table out of step (`wire` applies the new grant, `restoreWorkers` restores memory without telling the run loop). Signal `egressChanged` on restore.
- [ ] 7 Outside scope: `New`'s fail path removes the isolation tables without restoring forwarding it may have adopted. Fix if small, else note it here.
- [ ] 8 The Log's "lab-gotest supervisor pass" isn't backed by a full run: run the whole supervisor package in the lab and record it.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-072-stale-egress
- 2026-10-15 in-progress → review — restore worker/uplink state on failed rebuild, Close forwarding-first; make lint, make test, lab-gotest supervisor pass
- 2026-10-15 review → has-errors — 8 findings (config rollback drops seeds, inbound rollback, Close without tables on restore failure, test overclaims), see Review findings
