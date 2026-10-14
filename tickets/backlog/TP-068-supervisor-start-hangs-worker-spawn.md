---
id: TP-068
title: "Supervisor start hangs when a worker fails to spawn"
milestone: M2
area: agent/supervisor
repo: thinkpol-vpn
size: S
depends_on: []
owner: ""
branch: ""
---

## Goal
When a worker process fails to start, `thinkpol up` returns an error instead of blocking forever.

## Scope
- Fix `internal/agent/supervisor/supervisor_linux.go:1094-1110`: in `start()`, when `cmd.Start` fails the goroutine must close `p.gone` before returning so the caller is not left blocking on `<-p.gone` indefinitely.

## Out of scope
- Other supervisor lifecycle bugs; sandbox policy changes.

## Acceptance
- [ ] a worker spawn failure (e.g. user namespaces refused) surfaces as an error from server start, with a test that would have hung before the fix

## Notes
- **Independent review (2026-10-15):** `supervisor_linux.go:1094-1110` — on `cmd.Start` failure the goroutine returns without closing `p.gone`; the caller blocks on `<-p.gone` forever. Failure scenario: a VPS whose kernel refuses user namespaces, or a Docker host without the `pivot_root` seccomp rule TP-019 found, hangs `thinkpol up` instead of reporting an error.

## Log
- 2026-10-15 created in backlog
