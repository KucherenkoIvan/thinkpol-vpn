---
id: TP-071
title: "Data-frame %16 check breaks leader-following on shaped MTUs"
milestone: M2
area: dataplane/path
repo: thinkpol-vpn
size: S
depends_on: []
refs: [N2, DESIGN#data-plane]
owner: agent-composer
branch: tp-071-data-frame-mod16
---

## Goal
Leader following works under bulk traffic when the overlay MTU is not a multiple of 16 bytes.

## Scope
- `internal/dataplane/path/frame.go:102` requires a data message to be a multiple of 16 bytes; wireguard-go pads to `min(roundup16(len), mtu)`, so a full-MTU packet on a shaped overlay MTU that is not a multiple of 16 (e.g. 1228 for random padding, 1276 for a 1400 bucket) is never counted as a sign of life, `lastSeen` is never set on the new entry (`bind.go:284`), and `follow` at `bind.go:398` stays false.

## Out of scope
- Shaping contract changes beyond what path needs to recognise life signs.

## Acceptance
- [x] a test with a shaped MTU, bulk traffic and following: the follower follows the leader — `TestFollowerWithShapedOverlayMTU` in `internal/dataplane/path/shaped_mtu_test.go`

## Notes
- **Independent review (2026-10-15):** unshaped 1328 is safe, which is why no test caught it.
- **Data-frame length rule (round 2):** `wgDataLen` in `frame.go` accepts content `n-32` when `content%16 == 0` (wireguard-go's usual padding) or `content >= minOverlayMTU` (576, same as `dataplane.MinOverlayMTU`). Capped full-MTU frames on the sender use the sender's overlay floor, which is always at least 576, so the rule does not need the receiver's MTU. That still rejects sub-576 junk that is not a multiple of 16; oversized TUN reads that pad via `lastUnit %= mtu` can land in the second branch when content ≥ 576.

## Review findings
From independent review, 2026-10-15.
- [x] **Blocker:** `wgDataLen` checks capped full-MTU frames against the receiver's own TUN MTU, but wireguard-go pads to the sender's MTU; per-node overlay MTUs differ until TP-030, so a follower with a larger MTU never counts the leader's full-MTU frames as signs of life.
- [x] **Should-fix:** nothing tests the engine wiring (`engine.go` `SetWireGuardMTU`); if the length rule is sender-independent, that call and per-bind MTU state should go away.
- [x] **Nit:** TUN packets larger than the device MTU get WireGuard lengths that are neither a multiple of 16 nor `32+MTU` (`calculatePaddingSize` uses `lastUnit %= mtu`).

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: agent-composer, branch: tp-071-data-frame-mod16
- 2026-10-15 in-progress → review — capped full-MTU data frames count as signs of life; make lint and make test pass
- 2026-10-15 review → has-errors — receiver-MTU data-frame rule; see Review findings
- 2026-10-15 has-errors → in-progress — owner: agent-composer, fixing review findings
- 2026-10-15 in-progress → review — sender-independent `wgDataLen`; mismatched-MTU follower test; make lint, make test and dataplane race pass
