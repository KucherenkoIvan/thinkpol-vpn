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
When a worker fails to spawn, nothing hangs on shutdown or space removal; the supervisor keeps the async model (the worker restarts with backoff, as in DESIGN.md), and status/health show the spawn error.

## Scope
- Fix `internal/agent/supervisor/supervisor_linux.go:1094-1110`: in `start()`, when `cmd.Start` fails the goroutine must close `p.gone` before returning so the caller is not left blocking on `<-p.gone` indefinitely.
- Carry the worker's last spawn/exit reason through agent status, the local API and `thinkpol status`.

## Out of scope
- Other supervisor lifecycle bugs; sandbox policy changes.

## Acceptance
- [x] a worker spawn failure does not hang `Close` or `SetSpaces` removal — `TestWorkerSpawnFailureSurfaces` (lab)
- [x] spawn/exit reason visible on status and in the CLI — `TestWorkerLastExitReachesStatusAndCLI`
- [x] `make lint`, `make test`, and lab-gotest for `./internal/agent/supervisor/...` and `./internal/agent/...` pass

## Notes
- **Symptom (round 1):** on `cmd.Start` failure the supervise goroutine returned without closing `p.gone`, so `start()` blocked forever. That hung `Close` (`stopAll` waits on `<-w.done`) and could hang `SetSpaces` when removing a space while holding `setMu` if the worker had failed silently.
- Close `p.gone` on `cmd.Start` failure so `start()` returns and `run()` records `start: …` in `LastExit`. `SetSpaces` still returns nil; the server keeps running and the worker backs off (DESIGN.md "one worker per space").
- `TestWorkerSpawnFailureSurfaces` uses a missing worker binary.

## Review findings
Round 2 (2026-10-15).
- [x] 1. Goal, Acceptance and Notes misstate the symptom and expected behaviour (`SetSpaces` returns nil; server keeps running with backoff per DESIGN.md); pivot_root scenario is wrong.
- [x] 2. Spawn/exit reason not exposed on `WorkerStatus` / local API / CLI (`internal/agent/status.go`, proto, render).
- [x] 3. `TestWorkerSpawnFailureSurfaces` missing `t.Cleanup(s.Close)` (lab hygiene).
- [x] 4. Log has no lab run of `TestWorkerSpawnFailureSurfaces`.

Round 3 (2026-10-15).
- [ ] 1. `TestWorkerSpawnFailureSurfaces` does not exercise `SetSpaces` removal before `Close`.
- [ ] 2. Goal claims health shows the spawn error; health only reports `worker_down` (fix Goal text).
- [ ] 3. No unit test for `LastExit` in `report.status()` (`internal/agent/status.go:202`).

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-068-supervisor-spawn-hang
- 2026-10-15 in-progress → review — close p.gone on spawn failure; make lint and make test pass
- 2026-10-15 review → has-errors — round 2 review findings 1–4 (see Review findings)
- 2026-10-15 has-errors → in-progress — owner: agent-composer, fixing round 2 findings
- 2026-10-15 corrected Goal, Acceptance and Notes (removed wrong pivot_root scenario; async backoff model)
- 2026-10-15 lab-gotest PKG=./internal/agent/supervisor/... LAB_P=1 GOFLAGS=-p=4 — PASS (TestWorkerSpawnFailureSurfaces included)
- 2026-10-15 lab-gotest PKG=./internal/agent/... LAB_P=1 GOFLAGS=-p=4 — PASS (6 packages)
- 2026-10-15 in-progress → review — round 2 findings fixed; make lint and make test pass
- 2026-10-15 review → has-errors — round 3 review findings 1–3 (see Review findings)
