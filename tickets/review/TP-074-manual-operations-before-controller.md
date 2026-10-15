---
id: TP-074
title: "Manual operations before the controller"
milestone: M2
area: ops
repo: thinkpol-vpn
size: M
depends_on: []
refs: [A4, S2]
owner: "claude-tp074"
branch: "tp-074-manual-ops"
---

## Goal
The pre-M4 operating model is documented and tooled: map distribution, restarts, updates and clock setup without a controller.

## Scope
- A runbook for the period before M4: copying `map.bin` to nodes, restarting after VPS reboots, updating binaries over SSH.
- A map-rotation helper command.
- chrony/NTP setup (also referenced from TP-038).

## Out of scope
- Anything the controller (M4) automates.
- A `clock_skew` health code: cut in round 3, now TP-090.

## Acceptance
- [x] runbook committed and covers map copy, reboot recovery and binary updates over SSH
- [x] map-rotation helper command exists and is documented in the runbook
- [x] chrony/NTP setup documented for nodes

## Notes
- **Independent review (2026-10-15):** until M4 there is no ticket for hand-operated map distribution, reboot recovery, or clock checks.
- **Round 3 scope decision: `clock_skew` health cut to TP-090.** Rounds 1-2 couldn't make it unforgeable. On the round-2 head (2a006c3), one captured datagram replayed 3 times to a fresh router got the `StaleClock` verdict 3 times, which met the health threshold of 3. The fix needs new replay-filter state (stale datagrams counted only past the filter's creation time, de-duplicated, evicted ids kept for the connection-id window), a sliding window, race-free folding and real engine and supervisor tests. That's more than one last round can land and prove, so every clock_skew code path is reverted to `rewrite` as merged. No partial counters are kept: without the health code they only reclassified drops already counted as `StaleTimestamp`, and they carried their own nits. Round-1 findings 1-5 describe the cut code.

## Review findings
Round 1 review (cross-family, 2026-10-15):

- [x] **1** Forgeable `clock_skew` via replayed old sealed times — `wouldReplay` peek before `StaleClock`; health needs ≥3 drops in 5 min (`replay.go`, `router.go`, `listener.go`, `dialer.go`, `status.go`).
- [x] **2** Dialed links with only stale datagrams never fold stale-clock counts — `foldStaleClock` on link tick, close, and `Node.Counters()` (`path/link.go`, `path/node.go`).
- [x] **3** Server `clock_skew` timestamp used wall Unix nanoseconds — `atomic.Pointer[time.Time]` on supervisor shared (`supervisor/shared.go`, `supervisor_linux.go`).
- [x] **4** Listener drop time stamped at `Status()` — `noteStaleClock` records at drop; engine reads `StaleClockAt` (`udp/transport.go`, `engine.go`).
- [x] **5** Test gaps — `TestRouterStaleSender`, `TestReplayedOldDatagramDoesNotCountAsStaleClock`, `TestGenuinelySkewedPeerCountsAsStaleClock`, `TestFoldStaleClock`, burst/engine/supervisor/status/localapi tests; `TestDevMapRotate` uses default `NextVersion`.
- [x] **6** Runbook accuracy — build re-keys all links, devices, atomic install, keygen commands, recovery-out, mktemp, rotate check wording, systemd unit name (`docs/runbook-pre-controller.md`).
- [x] **N** `dev map rotate` logic in `devmap.Rotate` (`internal/devmap/plan.go`); health problem order; engine unregisters stale-clock feeds; server `stale_clock` in local API.

Round 2 delta review (Claude, 2026-10-15):

- [x] **B1** (blocker) `clock_skew` is still forgeable. A stale datagram only reaches the read-only `wouldReplay`, never `admit`, so nothing records it: the same captured datagram replayed 3 times counts 3 times and meets `staleClockHealthMin`. Senders are unknown after a receiver restart, on every redial (a new `dialLink` has empty `senders`), once an evicted id expires, and for withheld datagrams. → Cut: the clock_skew code is reverted, and TP-090 carries this review as its spec.
- [x] **S1** Runbook staging is broken (`docs/runbook-pre-controller.md:90-92, 143-151`): `mktemp -d` runs on the admin's machine; `cp` over `map.bin` isn't atomic. → `staging=$(ssh root@<node> mktemp -d)`; the map goes to `.map.new` in the state dir, then `mv -f` over `map.bin`; the binary goes to `/usr/local/bin/.thinkpol.new`, then `mv -f`.
- [x] **S2** `systemctl kill -s HUP thinkpol` signals the whole cgroup, and workers exit on SIGHUP (`main.go:18` handles only INT and TERM). → The unit gets `ExecReload=/bin/kill -HUP $MAINPID`; the runbook relies on the 5 s map poll, or `systemctl reload thinkpol`, and warns against `systemctl kill`. Verified: workers go to their own leaf under `/sys/fs/cgroup/thinkpol` (`supervisor/cgroup_linux.go:34`), which is outside the unit when cgroup v2 can be used, but they stay in the unit's cgroup in the rlimits-only fallback, and `worker` handles only INT and TERM.
- [x] **S3** Unregistering a listener breaks `staleClockFolded` (`engine.go:597-606, 715-723`). → Cut with clock_skew (TP-090 scope).
- [x] **S4** `foldStaleClock` runs on several goroutines and can underflow uint64 (`link.go:454-456`). → Cut with clock_skew (TP-090 scope).
- [x] **S5** `clockburst` is a fixed window anchored at the first drop, which flaps. → Cut with clock_skew (TP-090 scope).
- [x] **S6** Tests don't exercise the fixes: engine tests copy `Status`/`Serve` logic, `TestFoldStaleClock` calls fold directly, the supervisor test is stub-only, `TestWouldReplay` lacks the unseen-in-window and evicted cases and a no-mutation check. → Cut with the code they tested; TP-090's acceptance requires real-code tests.
- [x] **N2** Nits: `wouldReplay`'s both-branches-true and its comment (`replay.go:193-197`); garbled runbook health wording (180-184); contradictory device advice (82-84 vs 101-102); listener drops added to the burst at `Status` time (`engine.go:716`); `TestDevMapRotate` hits the "one past" branch only within the same second. → The replay.go and engine nits are cut with the code. The runbook health text is replaced by a "Spotting a clock that is off" item that says status has no clock problem yet (TP-090). The device advice is one ordered list (devices first, then servers in parallel). `TestDevMapRotate` pins both `NextVersion` branches: a deployed map at 4000000000 rotates to exactly 4000000001, and one at 5 rotates to the current Unix time.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: glm-tp074
- 2026-10-15 in-progress → review — pre-controller runbook, dev map rotate, clock_skew health; make lint and make test on darwin
- 2026-10-15 review → has-errors — round 1 cross-family review (see Review findings)
- 2026-10-15 has-errors → in-progress — round 2 fixes
- 2026-10-15 in-progress → review — round 2: merged rewrite (TP-070), replay-safe clock_skew, runbook and tests; make lint and make test on darwin
- 2026-10-15 review → has-errors — round 2 delta review: 1 blocker, 6 should-fix, nits (see Review findings)
- 2026-10-15 has-errors → in-progress — owner: claude-tp074, round 3 (last) fixes
- 2026-10-15 in-progress → review — round 3: clock_skew health cut to TP-090 (B1 forgery reproduced on 2a006c3), runbook staging/rename/reload fixed, rotate test pins both version branches; make lint, make test and go test -race (cmd/thinkpol, devmap, dataplane/..., agent/...) pass on darwin. Not run: the runbook's ssh/systemd commands on a real node (no host may be contacted), the lab.
- 2026-10-15 docs: TP-074 review nits — runbook rollback/devices/chrony/staging, DESIGN device map delivery, TP-090 spec tightened
