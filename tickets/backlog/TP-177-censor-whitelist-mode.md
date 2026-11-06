---
id: TP-177
title: "Censor module: whitelist mode"
milestone: later
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-032]
split_from: TP-032
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab reproduces whitelist mode, including its UDP drop to listed addresses.

## Scope
- Whitelist mode, as docs/design/lab.md describes it: drop everything whose destination address isn't listed, then check the handshake's name (SNI) on what's left; drop UDP even to listed addresses; variants that throttle the rest to about 14 kb/s, reset it, or let it time out. A name-only check (address not checked) is a separate, weaker module.

## Out of scope
- JA3/JA4 allow-list and volume throttling: TP-032.
- Passing whitelist mode through an allowlisted entry: TP-178.

## Acceptance
- [ ] whitelist mode drops a disguised handshake carrying a listed name to an unlisted address
- [ ] UDP to a listed address is dropped; TCP to it passes
- [ ] each variant (drop, throttle, reset, time out) has a matrix column, and so does the name-only module

## Notes
- Split from TP-032, 2026-11-07, owner's MVP cut. The owner deferred whitelist mode: research is ongoing.

## Log
- 2026-11-07 created in backlog (split from TP-032)
