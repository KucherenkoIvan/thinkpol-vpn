---
id: TP-071
title: "Data-frame %16 check breaks leader-following on shaped MTUs"
milestone: M2
area: dataplane/path
repo: thinkpol-vpn
size: S
depends_on: []
owner: ""
branch: ""
---

## Goal
Leader following works under bulk traffic when the overlay MTU is not a multiple of 16 bytes.

## Scope
- `internal/dataplane/path/frame.go:102` requires a data message to be a multiple of 16 bytes; wireguard-go pads to `min(roundup16(len), mtu)`, so a full-MTU packet on a shaped overlay MTU that is not a multiple of 16 (e.g. 1228 for random padding, 1276 for a 1400 bucket) is never counted as a sign of life, `lastSeen` is never set on the new entry (`bind.go:284`), and `follow` at `bind.go:398` stays false.

## Out of scope
- Shaping contract changes beyond what path needs to recognise life signs.

## Acceptance
- [ ] a test with a shaped MTU, bulk traffic and following: the follower follows the leader

## Notes
- **Independent review (2026-10-15):** unshaped 1328 is safe, which is why no test caught it.

## Log
- 2026-10-15 created in backlog
