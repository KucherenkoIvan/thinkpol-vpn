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
The pre-M4 operating model is documented and tooled: map distribution, restarts, updates and clock health without a controller.

## Scope
- A runbook for the period before M4: copying `map.bin` to nodes, restarting after VPS reboots, updating binaries over SSH.
- A map-rotation helper command.
- A clock-skew health code (nodes must agree within 5 minutes).
- chrony/NTP setup (also referenced from TP-038).

## Out of scope
- Anything the controller (M4) automates.

## Acceptance
- [x] runbook committed and covers map copy, reboot recovery and binary updates over SSH
- [x] map-rotation helper command exists and is documented in the runbook
- [x] health reports clock skew beyond 5 minutes
- [x] chrony/NTP setup documented for nodes

## Notes
- **Independent review (2026-10-15):** until M4 there is no ticket for hand-operated map distribution, reboot recovery, or clock checks.
- Worker-process dialed-link stale-clock counts still do not reach server health (only shared routers do); left for a follow-up.

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

- [ ] **B1** (blocker) `clock_skew` is still forgeable. A stale datagram only reaches the read-only `wouldReplay`, never `admit`, so nothing records it: the same captured datagram replayed 3 times counts 3 times and meets `staleClockHealthMin`. Senders are unknown after a receiver restart, on every redial (a new `dialLink` has empty `senders`), once an evicted id expires, and for withheld datagrams.
- [ ] **S1** Runbook staging is broken (`docs/runbook-pre-controller.md:90-92, 143-151`): `mktemp -d` runs on the admin's machine; `cp` over `map.bin` isn't atomic.
- [ ] **S2** `systemctl kill -s HUP thinkpol` signals the whole cgroup, and workers exit on SIGHUP (`main.go:18` handles only INT and TERM).
- [ ] **S3** Unregistering a listener breaks `staleClockFolded` (`engine.go:597-606, 715-723`).
- [ ] **S4** `foldStaleClock` runs on several goroutines and can underflow uint64 (`link.go:454-456`).
- [ ] **S5** `clockburst` is a fixed window anchored at the first drop, which flaps.
- [ ] **S6** Tests don't exercise the fixes: engine tests copy `Status`/`Serve` logic, `TestFoldStaleClock` calls fold directly, the supervisor test is stub-only, `TestWouldReplay` lacks the unseen-in-window and evicted cases and a no-mutation check.
- [ ] **N2** Nits: `wouldReplay`'s both-branches-true and its comment (`replay.go:193-197`); garbled runbook health wording (180-184); contradictory device advice (82-84 vs 101-102); listener drops added to the burst at `Status` time (`engine.go:716`); `TestDevMapRotate` hits the "one past" branch only within the same second.

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
