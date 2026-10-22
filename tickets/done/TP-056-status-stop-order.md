---
id: TP-056
title: "Data plane stop publishes a whole status, never a mixed one"
milestone: M1
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-020]
refs: [docs/design/desktop-client.md#node-agent]
owner: agent-small-fixes
branch: tp-056-status-stop-order
---

## Goal
A status read while a device's data plane stops (removed from its space, disconnected, shutting down) shows either the state before or the state after, never a mix. Today `runner.stop()` (internal/agent/dataplane.go) publishes `engine = nil` on its own, before `publish()` sets the new map version, `removed` and `retrying`. A reader in between sees "connecting, old version, not removed", which is wrong for a UI or `thinkpol status` polling at that moment. Found by TP-055: agent `TestADeviceConnectsAndDisconnects` caught it 2 times in 40 under `-race`, and the test now waits for the exact state.

## Scope
- `stop()` publishes the whole report (as `publish()` does) with the engine gone, instead of `engine = nil` alone. Its callers already set `down`/`removed`/`cur` before calling it. Clear `retryAt` there too if that keeps the published state whole.
- A test that polls `Status()` concurrently while a node is removed and disconnected, and never sees a state that is neither before nor after.

## Out of scope
Anything else in the status model.

## Acceptance
- [x] no mixed state between stop and the next publish: the concurrent-poll test, many runs under `-race`
- [x] `make lint`, `make test`, `make test-race` on internal/agent

## Notes
- Waits for TP-020, which edits the lines around that `report.set` in `stop()` (resolver close, `restoreSystem`).
- **Done:** `runner.stop()` takes the engine, listeners and resolver out of the runner, clears `retryAt` and calls `publish()` before it restores DNS and closes anything; the report's engine is still cleared before the engine closes. Callers already set `down`/`removed`/`cur` first. Their own `retryAt` clears stay: they cover a stop with no engine (a start waiting for its retry), where `stop()` returns at once and the loop's next `publish()` is the only one.
- **Test:** `TestStatusIsWholeWhileTheDataPlaneStops` (`internal/agent/status_test.go`) polls `Status()` in a tight loop while the device is removed (map 2), comes back (map 3) and disconnects, and accepts only the four whole states. Before the fix it failed 5 of 5 runs (thousands of reads of "version 1, connecting, not removed" and "version 3, connecting"); after it, 20 runs plain and 40 under `-race` (with `TestADeviceConnectsAndDisconnects`) pass.

## Log
- 2026-10-12 created in backlog (TP-055 review follow-up)
- 2026-10-12 backlog → in-progress — owner: agent-small-fixes, branch: tp-056-status-stop-order
- 2026-10-12 in-progress → review — both acceptance boxes checked; `make lint`, `make test`, `go test -race ./internal/agent/...` pass; the new test fails 5/5 before the fix, passes 40/40 under `-race` after
- 2026-10-13 review → done — merged into rewrite (after TP-057: stop() keeps its clearRoutes() for a stop with nothing running)
