---
id: TP-056
title: "Data plane stop publishes a whole status, never a mixed one"
milestone: M1
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-020]
refs: [DESIGN#engine-and-agent]
owner: ""
branch: ""
---

## Goal
A status read while a device's data plane stops (removed from its space, disconnected, shutting down) shows either the state before or the state after, never a mix. Today `runner.stop()` (internal/agent/dataplane.go) publishes `engine = nil` on its own, before `publish()` sets the new map version, `removed` and `retrying`. A reader in between sees "connecting, old version, not removed", which is wrong for a UI or `thinkpol status` polling at that moment. Found by TP-055: agent `TestADeviceConnectsAndDisconnects` caught it 2 times in 40 under `-race`, and the test now waits for the exact state.

## Scope
- `stop()` publishes the whole report (as `publish()` does) with the engine gone, instead of `engine = nil` alone. Its callers already set `down`/`removed`/`cur` before calling it. Clear `retryAt` there too if that keeps the published state whole.
- A test that polls `Status()` concurrently while a node is removed and disconnected, and never sees a state that is neither before nor after.

## Out of scope
Anything else in the status model.

## Acceptance
- [ ] no mixed state between stop and the next publish: the concurrent-poll test, many runs under `-race`
- [ ] `make lint`, `make test`, `make test-race` on internal/agent

## Notes
- Waits for TP-020, which edits the lines around that `report.set` in `stop()` (resolver close, `restoreSystem`).

## Log
- 2026-10-12 created in backlog (TP-055 review follow-up)
