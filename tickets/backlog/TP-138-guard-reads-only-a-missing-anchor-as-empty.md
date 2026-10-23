---
id: TP-138
title: "macOS guard: only a missing anchor's answer reads as an empty anchor"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
needs_human: macos
depends_on: []
refs: [D6, docs/design/security.md#ipv6]
owner: ""
branch: ""
---

## Goal
The pf guard on macOS treats only pfctl's missing-anchor answer as an empty anchor. Any other "Invalid argument" from pfctl is an error the guard reports, not an empty ruleset.

## Scope
- In `internal/dataplane/firewall` (darwin), the guard's `invalidArgument` check, used by `listRules` and `flush`, reads any stderr containing "Invalid argument" as "the anchor doesn't exist". A different pfctl failure that answers "Invalid argument" (e.g. DIOCADDRULE) is therefore taken for an empty anchor instead of being reported.
- TP-082 (device-test harness, branch `tp-082-device-harness`) adds `firewall.AnchorMissing`, which accepts only `pfctl: DIOCGETRULES: Invalid argument`. That string is taken from pfctl's source and has not yet been seen on a Mac.
- Once TP-082 merges, move the guard to that same reader, so there is one definition of the missing-anchor answer.

## Out of scope
- The device-test harness and `firewall.AnchorMissing` themselves: they belong to TP-082.
- Changing how the guard handles errors other than "Invalid argument".

## Acceptance
- [ ] `listRules` and `flush` use the one reader (`firewall.AnchorMissing`, from TP-082)
- [ ] a test: pfctl answering another "Invalid argument" (e.g. DIOCADDRULE) is reported as an error, not as an empty anchor
- [ ] the missing-anchor message is recorded from a real Mac run (see Notes)

## Notes
- The exact pfctl message for a missing anchor is to be confirmed on the owner's Mac: run `listRules` and `flush` against an anchor that does not exist, and record the stderr line here. TP-082's device checklist records the check.
- The third box waits on that Mac run; it stays unchecked until the result is written here.
- The move to `firewall.AnchorMissing` waits for TP-082 to merge. This ticket has no `depends_on` entry for it, so the ordering is by hand.

## Log
- 2026-10-23 created in backlog (TP-082 round 2: the guard's missing-anchor check accepts any Invalid argument)
