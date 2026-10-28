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
owner: "agent-claude-tp138"
branch: "tp-138-guard-reads-only-a-missing-anchor-as-empty"
---

## Goal
The pf guard on macOS treats only pfctl's missing-anchor answer as an empty anchor. Any other "Invalid argument" from pfctl is an error the guard reports, not an empty ruleset.

## Scope
- In `internal/dataplane/firewall` (darwin), the guard's `invalidArgument` check, used by `listRules` and `flush`, reads any stderr containing "Invalid argument" as "the anchor doesn't exist". A different pfctl failure that answers "Invalid argument" (e.g. DIOCADDRULE) is therefore taken for an empty anchor instead of being reported.
- TP-082 (device-test harness, branch `tp-082-device-harness`) adds `firewall.AnchorMissing`, which accepts only `pfctl: DIOCGETRULES: Invalid argument`. That string is taken from pfctl's source and has not yet been seen on a Mac.
- Once TP-082 merges, move the guard to that same reader, so there is one definition of the missing-anchor answer.
- **Widened (2026-10-24): pfctl's `No pf starter references held`.** With no reference held, `pfctl -s References` prints only that line, no `PID … TOKEN` header. `parseReferences` (`internal/dataplane/firewall/pfctl_darwin.go` ~302–323) needs the header, so it returns not understood, and `release` takes the listing as unreadable: Close fails and keeps a record for a reference that no longer exists, and the diag's held check misreads it the same way. Read that exact text as an empty References listing; anything else without a header stays unreadable.
- **Recorded fixtures.** Commit the pfctl listings recorded on the device (`-s rules -v`, `-T show`, `-s info`, `-s References` with and without references, `-s rules`, `-s Interfaces -v`, `-a com.apple -s Anchors`, the missing anchor's stderr) and the `scutil --dns` listings as test fixtures in `firewall/testdata/pfctl` and `dns/testdata/scutil`, beside or in place of the built ones. They are sanitized first: no IP addresses, no hostnames (overlay, endpoint, upstream and resolver addresses replaced by documentation addresses, `example.net` for names). This also closes TP-091's two open boxes (pf and `scutil --dns` parsed from recorded fixtures).

## Out of scope
- The device-test harness and `firewall.AnchorMissing` themselves: they belong to TP-082.
- Changing how the guard handles errors other than "Invalid argument".

## Acceptance
- [x] `listRules` and `flush` use the one reader (`firewall.AnchorMissing`, from TP-082)
- [x] a test: pfctl answering another "Invalid argument" (e.g. DIOCADDRULE) is reported as an error, not as an empty anchor
- [x] the missing-anchor message is recorded from a real Mac run (see Notes)
- [x] a test on the recorded fixture: `No pf starter references held` reads as no references, understood; Close after it removes the record
- [x] the recorded pfctl and `scutil --dns` listings are committed as sanitized fixtures (no IPs, no hostnames) and the parsers' tests run on them; TP-091's two fixture boxes are ticked, with a Log line there

## Notes
- The exact pfctl message for a missing anchor is to be confirmed on the owner's Mac: run `listRules` and `flush` against an anchor that does not exist, and record the stderr line here. TP-082's device checklist records the check.
- The third box waits on that Mac run; it stays unchecked until the result is written here.
- The move to `firewall.AnchorMissing` waits for TP-082 to merge. This ticket has no `depends_on` entry for it, so the ordering is by hand.
- **Device evidence (the 2026-10-24 macOS device run).** `pfctl: DIOCGETRULES: Invalid argument` was seen for the missing guard anchor after uninstall and after a reboot. `No pf starter references held` was the whole References listing after every reboot (this Mac's `socketfilterfw` reference doesn't come back) and after the uninstall. The guard's Close at uninstall still removed its record, so the misread path wasn't hit there.
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, Guard): done before the M2 lanes start. Both are pfctl answers the guard misreads, both now seen on a Mac, and the guard's record and Close feed the kill switch (TP-048).
- **Recorded answers (read from the 2026-10-24 run's files, 2026-10-28).** The missing anchor's `-a com.apple/000.thinkpol -s rules` answer is exactly `pfctl: DIOCGETRULES: Invalid argument`, the one `listRules` runs; it was captured with stdout and stderr together and ALTQ chatter filtered, so its stream and exit status aren't recorded (pfctl's `err()` writes it to stderr and exits 1). The missing table's `-T show` answer is `pfctl: Table does not exist.`, for the missing anchor's table too. `No pf starter references held` is on stdout, alone, ALTQ chatter on stderr; the exit status isn't recorded (a non-zero one would still fail the Close, closed). What `-F rules`/`-F Tables` answer for a missing anchor isn't recorded: `flush` no longer reads it (below).
- **Decisions (2026-10-28).** TP-082 isn't merged, and the Guard lane runs first, so `firewall.AnchorMissing` lands here, with TP-082's name, signature and doc, one difference: a listing cut by a line too long to read isn't the answer. TP-082 drops its copy (listing_darwin.go) and its doc.go sentence "The guard moves to [AnchorMissing] in TP-138" when it merges `rewrite`. `noTable` is narrowed the same way (it used the old Invalid-argument test): exactly `pfctl: Table does not exist.` or `pfctl: Anchor or Ruleset does not exist.`, pfctl's own words for ESRCH and ENOENT. `flush` no longer gates on what a failed `-F` printed: the anchor's listings (`listRules`, `listTable`) decide, so the missing-anchor reader is the only one, and a failed `-F` over an anchor that still lists a rule or the table fails the Close as before.

## Log
- 2026-10-23 created in backlog (TP-082 round 2: the guard's missing-anchor check accepts any Invalid argument)
- 2026-10-24 scope widened (2026-10-24 macOS device run): `No pf starter references held` read as an empty listing; the recorded listings committed as sanitized fixtures, closing TP-091's two fixture boxes; before-M2 list
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Guard)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp138
- 2026-10-28 6ef4cd1: `firewall.AnchorMissing` (pfctl_darwin.go) is the guard's one missing-anchor reader (`listRules`, `inspect`; `flush` decides by the listings only); `noTable` exact; `parseReferences` reads `No pf starter references held` alone as no references, understood; the fake pf answers as the Mac did (References with none, a missing anchor's table); the device run's pfctl and `scutil --dns` listings committed sanitized as `recorded-*` fixtures, replacing the built ones they cover (info both ways, anchors, main, References, an empty anchor; the built scutil baseline and connected)
- 2026-10-28 tests: `TestPfctlsNoAnswersAreExact`, `TestAnotherInvalidArgumentIsNoEmptyAnchor` (a DIOCADDRULE "Invalid argument" on the rules or table listing after a failed flush fails the Close, which keeps anchor, reference and record; the snapshot says unreadable), `TestCloseAfterAnOutsideReleaseRemovesTheRecord` (the fake's References equals the recorded fixture byte for byte), `TestTheRecordedListingsParse` (saneRules accepts the recorded rules, and the fake lists the guard's rules exactly as the Mac did), `TestParseScutilDNS` on the three recorded listings. Mutations, each caught: AnchorMissing on any Invalid argument; noTable's Invalid-argument arm back; no noReferences branch; noReferences anywhere in the listing; onlyLine ignoring a cut listing; flush taking a failed rules listing for empty; flush skipping the table check; inspect or listRules taking any failure for a missing anchor; scutil's scoped section unmarked, an empty value refused, if_index's interface dropped
- 2026-10-28 TP-091's two fixture boxes ticked, with a Log line there; `make lint` and `make test` pass. No `make lab-test`: every changed line of code is in a darwin-only file (the lab runs Linux nodes), the rest are comments and fixtures. Not verified on a Mac: pfctl's exit status with `No pf starter references held`, and what `-F` answers for a missing anchor
- 2026-10-28 in-progress → review
