---
id: TP-137
title: "macOS guard: kill the states pf passed while off even when the new token can't be read"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: [D6, docs/design/security.md#ipv6]
owner: "agent-claude-tp137"
branch: "tp-137-macos-guard-kills-states-without-a-token"
---

## Goal
When pf was turned off under the guard, the Apply that turns it back on kills the IPv6 states made while it was off, even if `pfctl -E`'s token can't be read.

## Scope
- Today `takeReference` returns `errUnreadToken` when `pfctl -E` prints no token that `pfctl -s References` can name, and `Apply` (`firewall/guard_darwin.go`) returns at once, before the bypass check and the state kill. Each retry meets the same error in `resolveToken` for as long as the token stays unnamed, so states pf passed while it was off keep passing.
- Let `Apply` carry on through the bypass check and the kill after `errUnreadToken`, and report it at the end, as TP-091's round 4 did for a failed release of the old reference. Say so in firewall/doc.go.
- Dates from TP-078; it changes the guard's behaviour, so it isn't part of TP-091.

## Acceptance
- [ ] a test: with the new token unreadable, a state made while pf was off is killed in the same Apply, and the Apply still returns `errUnreadToken`; it fails if Apply returns early
- [ ] firewall/doc.go says the Apply finishes enforcing, then reports the unread token
- [ ] `make lint`, `make test` pass

## Notes
- From TP-091's round-5 design review (2026-10-23).
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Guard lane: last, after TP-129 (the same two pf files).

## Log
- 2026-10-23 created in backlog (TP-091 review round 5)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-29 backlog → in-progress, owner: agent-claude-tp137
