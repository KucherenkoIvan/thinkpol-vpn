---
id: TP-143
title: "macOS guard: does pf mark a skipped interface at all?"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
needs_human: macos
depends_on: [TP-144]
refs: [RR12, D6, docs/design/security.md#ipv6]
owner: ""
branch: ""
---

## Goal
What RESIDUAL-RISKS.md says about a skipped interface on macOS is true. Either the guard really sees `set skip on` and reports it, or the claim is corrected and the gap is named.

## Scope
- On the device `pfctl -s Interfaces -v` printed bare names, with no `(skip)` and no counters, even after `set skip on lo`. The guard's `SkippedNames` (`internal/dataplane/firewall/pfctl_darwin.go` ~230–248) matches only `<name> (skip)`, so it may never see a skip on this macOS.
- Find out: TP-144's device re-run loads `set skip on lo0` too (the real interface, not only the `lo` group name) and records `pfctl -s Interfaces -v` and health.
- If pfctl never shows a skip, read the skip set some other way (another pfctl listing, `-s info`, an ioctl through pfctl's own output; no cgo) and test it on the recorded listing.
- Or, if there is no way to read it, correct RESIDUAL-RISKS.md RR12 and `firewall/doc.go` (~181), which claim a skipped interface is reported within about 10 s, and say the skip is unseen, as RR12 already does for a quick pass inside an earlier anchor.

## Out of scope
- Undoing another program's skip: TP-126 decided the guard reports, never undoes.
- The native-IPv6 leak paths: TP-096.

## Acceptance
- [ ] TP-144's run records `pfctl -s Interfaces -v` after `set skip on lo` and after `set skip on lo0`, written into Notes
- [ ] either: a skip is read and reported on a recorded listing (a unit test on the sanitized fixture), or RR12 and `firewall/doc.go` say the skip isn't seen
- [ ] `make lint`, `make test` pass

## Notes
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 3): done before the M2 lanes start. RR12 is a published safety claim, and TP-048's kill switch is built on the same pf reads.
- **Device evidence (the 2026-10-24 macOS device run, steps 1, 6 and 20).** The listing was identical before connecting, with the guard applied, and after `set skip on lo`: bare names, no `lo (skip)` and no marked `lo0`. Health stayed ok at 20 s and 77 s. The listings are in TP-096's Notes.
- TP-096 recorded the listing and ticked its box; the question whether macOS marks skips at all moved here.
- Depends on TP-144 for the `lo0` run.

## Log
- 2026-10-24 created in backlog (2026-10-24 macOS device run, step 20: before-M2 list)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 3)
