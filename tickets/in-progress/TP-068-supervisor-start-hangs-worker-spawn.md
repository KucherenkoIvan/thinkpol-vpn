---
id: TP-068
title: "Supervisor start hangs when a worker fails to spawn"
milestone: M2
area: agent/supervisor
repo: thinkpol-vpn
size: S
depends_on: []
refs: [N5, DESIGN#server-agent-one-worker-per-space]
owner: agent-composer
branch: tp-068-supervisor-spawn-hang
---

## Goal
When a worker process fails to start, `thinkpol up` returns an error instead of blocking forever.

## Scope
- Fix `internal/agent/supervisor/supervisor_linux.go:1094-1110`: in `start()`, when `cmd.Start` fails the goroutine must close `p.gone` before returning so the caller is not left blocking on `<-p.gone` indefinitely.

## Out of scope
- Other supervisor lifecycle bugs; sandbox policy changes.

## Acceptance
- [x] a worker spawn failure (e.g. user namespaces refused) surfaces as an error from server start, with a test that would have hung before the fix — `TestWorkerSpawnFailureSurfaces` (lab)

## Notes
- **Independent review (2026-10-15):** `supervisor_linux.go:1094-1110` — on `cmd.Start` failure the goroutine returns without closing `p.gone`; the caller blocks on `<-p.gone` forever. Failure scenario: a VPS whose kernel refuses user namespaces, or a Docker host without the `pivot_root` seccomp rule TP-019 found, hangs `thinkpol up` instead of reporting an error.
- Close `p.gone` on `cmd.Start` failure so `start()` returns and `run()` records `start: …` in `LastExit`; `TestWorkerSpawnFailureSurfaces` uses a missing worker binary.

## Review findings
Round 2 (2026-10-15).
- [ ] 1. Goal, Acceptance and Notes misstate the symptom and expected behaviour (`SetSpaces` returns nil; server keeps running with backoff per DESIGN.md); pivot_root scenario is wrong.
- [ ] 2. Spawn/exit reason not exposed on `WorkerStatus` / local API / CLI (`internal/agent/status.go`, proto, render).
- [ ] 3. `TestWorkerSpawnFailureSurfaces` missing `t.Cleanup(s.Close)` (lab hygiene).
- [ ] 4. Log has no lab run of `TestWorkerSpawnFailureSurfaces`.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-068-supervisor-spawn-hang
- 2026-10-15 in-progress → review — close p.gone on spawn failure; make lint and make test pass
- 2026-10-15 review → has-errors — round 2 review findings 1–4 (see Review findings)
- 2026-10-15 has-errors → in-progress — owner: agent-composer, fixing round 2 findings
