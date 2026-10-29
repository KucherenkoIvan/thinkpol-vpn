---
id: TP-124
title: "macOS: recover from a corrupt route record"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-claude-tp124"
branch: "tp-124-recover-from-a-corrupt-macos-route-record"
---

## Goal
A corrupt route record under `/private/var/db/thinkpol/netcfg` doesn't leave a device unable to connect until someone deletes the file by hand.

## Scope
- Today (TP-108) a corrupt record of another owner fails this node's route-table survey (and the default-route lookup) with an error naming the file; recovery was handed to TP-102, which didn't take it.
- Decide what is safe: a record that can't be parsed says nothing about which routes are whose. Options: quarantine the file and treat its owner's routes as foreign (never removed by us), or remove only routes that match a parsed record and leave the rest. Never delete routes we can't prove are ours.
- Health says a record was set aside, and the log names the file.

## Acceptance
- [x] a unit test with a corrupt record of another owner: the survey succeeds, the record is reported in place and its routes are `Held` (its owner sets it aside at its own start), no route of that owner is removed — `TestACorruptRecordOfAnotherOwnerIsReportedInPlace` (netcfg_darwin_test.go): a crashed overlay's routes and a corrupt overlay record; the route table's `DefaultRoute` (first, over the corrupt file) and `Survey` answer, the record is untouched and not set aside, `Survey.CorruptRecords` names it with why (`no boot line`), the overlay's routes are `Held` (foreign) and counted in `UnownedRoutes` (4, the route table's own routes not among them after its Apply), and after the route table's Apply and Close the kernel holds the overlay's routes unchanged; the overlay's next start sets the record aside at `overlay.routes.corrupt-<boot>`, owning nothing, and the next survey reports that file. `TestAnUnreadableRecordFailsTheSurvey`: a record that can't be read (mode 0) still fails the survey and DefaultRoute, nothing set aside
- [x] the same for the node's own record at start — `TestTheOwnersCorruptRecordIsSetAsideAtStart`: a crashed route table's routes and its corrupt record; the next configurator starts owning nothing, the record is set aside and reported, the leftovers are `Held` and counted in `UnownedRoutes`, an Apply over them fails with ErrConflict, and Close leaves the kernel unchanged
- [x] `make lint`, `make test` pass — both exit 0 on the code commit; `make lab-test` too (Log)

## Review findings
Round 1 (2026-10-28): correctness (no defect, test gaps), design (fix first), conventions (fix first). Setting a corrupt record aside and owning nothing holds; the cross-owner set-aside buys nothing with today's wiring and makes ErrBusy lie, and health follows a file instead of the leftover routes.
- [x] R1.1 (design 1, 8; correctness 6) Remove the cross-owner lock and set-aside from `recordOf` (`netcfg_darwin.go` ~619-646): another owner's corrupt record holds nothing and is reported in place, never touched; its owner sets it aside at its own next start, under its own lock. Rename the surface to what is measured (`Survey.CorruptRecords`, `Status.CorruptRecords`, the counter); drop `TestACorruptRecordOfARunningOwnerIsLeftToIt` (one case now). Update the acceptance evidence and add a Log line on the changed wording ("the record is set aside" → reported in place, its routes Held; its owner sets it aside at start), the Notes' decision and the device checklist.
- [x] R1.2 (design 2) Health follows the real problem: degraded only while a corrupt record is seen AND routes carrying routeFlag that no record names are in the kernel (`Survey.UnownedRoutes`), not merely while a file exists. Checklist step 3 says deleting the file is an acknowledgement, not a repair.
- [x] R1.3 (correctness 1) A test that an earlier boot's set-aside file isn't reported (catches the boot id dropped from `setAsideName`).
- [x] R1.4 (conventions 1, 2, 3; design 6, 7) The symlink case in the corrupt-record definitions (`netcfg/doc.go` ~60, `record_darwin.go` ~48); the stale comments on `owned` and `thinkpolRoutes`.
- [x] R1.5 (design 3) A failed stat for reporting never fails the survey.
- [x] R1.6 (design 4) Earlier boots' set-aside files are removed at the owner's start, under its own lock.
- [x] R1.7 (design 5; correctness 4; conventions 5) Setting a corrupt directory aside over an earlier set-aside entry (ENOTDIR, EISDIR, ENOTEMPTY): remove the target first, or document; narrow `trusteddir.Rename`'s doc to what renameat(2) replaces.
- [x] R1.8 (correctness 3) A corrupt record from before this boot (mtime before kern.boottime) is set aside but not reported.
- [x] R1.9 (correctness 5) The log says why a record was judged corrupt.
- [x] R1.10 (correctness 2) The DefaultRoute test meets a corrupt file (today it runs after Survey moved it).
- [x] R1.11 (conventions 4) The darwin `Survey` doc names the new fields.
- [x] R1.12 (conventions 6) Drop "(TP-124)" from `netcfg/doc.go`.
- [x] R1.13 (conventions 7) The problem code's plural/singular: choose one and say why.
- [x] R1.14 (conventions 8) The status line shows even when the route table holds no routes.
Round 2 (2026-10-29): design (fix first: S1, S2), correctness (merge, six suspicions and nits). The design holds; the user-facing text assumes a crashed owner and a set-aside file, and a repeat corruption goes unlogged.
- [x] R2.1 (design S1, N5) The in-place case (a live owner's record corrupted in place, no set-aside file): no text claims "until reboot" or "set-aside file" unconditionally. `render.go` status line (and its plural pronoun for one record), the routetable warn, the `status.go` problem doc, `dataplane/routetable.go`, `netcfg.go`, `agent/doc.go`, RR53. The checklist's step 1 expected string follows, and says whether `overlay_routes_ahead` (Down) is expected there, as the code does.
- [x] R2.2 (design S2; correctness 2) A record that goes away and comes back, or comes back with a new reason or mtime, is warned again: keep only what the latest survey saw. A test: report, clear, report again gives two warnings.
- [x] R2.3 (correctness 1) A socket (or another non-regular file whose open fails, EOPNOTSUPP) at the record path is corrupt, not a hard error: `fstatat` with NOFOLLOW before the open. A case in `TestRecordsRoundTrip`.
- [x] R2.4 (correctness 3; design N3) The mtime check is skipped when the record's boot line matched this boot; the doc says what remains of the mtime gate (a record from before this boot leaves no trace but the file).
- [x] R2.5 (correctness 4) A comment on the transient double count (a record reported in place, then set aside by its owner within one survey).
- [x] R2.6 (correctness 5) A corrupt `supervisor.routes` on darwin is never set aside (no darwin configurator): say so in the doc, or skip owners darwin can't run; choose and say why.
- [x] R2.7 (design N1) The raw directory work in `record_darwin.go` (`clearSetAside`, `removeEntry`) moves into trusteddir (`Names`, `RemoveEntry`).
- [x] R2.8 (design N2) `EEXIST` in `trusteddir.Rename`'s doc, or out of `setAside`'s retry.
- [x] R2.9 (design N4) A set-aside file that now parses still gets a non-empty Reason.
- [x] R2.10 (correctness 6) Test gaps, if cheap: a non-empty directory at the set-aside name, a symlink at an earlier boot's set-aside name, an `os.RemoveAll` mutant in `clearSetAside`.
Round 3 (2026-10-29): design (fix first: S1 wording only, then merge; nits), correctness (merge; T1, N1–N3). The orchestrator folded every point into one round and merges with no further review round.
- [x] R3.1 (design S1) Split on whether the owner was already running when its record went bad: "an owner already running when its record went bad still removes its own; the rest (a dead owner's, or a set-aside record's, whose owner restarted owning nothing) stay until reboot", in `render.go` (singular and plural), the routetable warn, `netcfg/doc.go`, Notes, checklist step 1's expected string and `TestACorruptRecordReachesStatusAndCLI`; the same split in `status.go`, `dataplane/routetable.go` and `netcfg.go`, which said "a running owner".
- [x] R3.2 (correctness N1) A dead overlay's routes go with its interface: "unless they went with their owner's interface" in the same places.
- [x] R3.3 (design nits) `netcfg/doc.go`: the long line rewrapped; "goes unreported (and is set aside if its owner starts)"; the supervisor's record "until someone removes it or the Mac reboots". `agent/doc.go`: the dead-owner branch. `record_darwin.go`: a hard re-read error's Reason without the path again.
- [x] R3.4 (correctness T1) `TestAnOverlaysRoutesSeenAsForeignAreNothingAhead` checks the layout is unchanged when the overlay's halves turn foreign (`maps.Equal` against the valid-record survey).
- [x] R3.5 (correctness N2) trusteddir's `openRegular`: EOPNOTSUPP and ENXIO from the open are `ErrNotRegular`; `O_NOCTTY`.
- [x] R3.6 (correctness N3) `RemoveEntry` returns the first error when the retry as a directory fails with ENOTDIR.

## Notes
- From TP-077's residual-risks research (2026-10-22); TP-108 R2.7 handed recovery to TP-102, which didn't add it.
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, macOS): done before the M2 lanes start. TP-108 made another owner's corrupt route record a hard connect failure, with no recovery but deleting the file by hand. The 2026-10-24 macOS device run's corrupt-record step was inconclusive; TP-144's re-run checks it again.

**Decision: own nothing; only the owner sets its record aside (2026-10-28, round 1).** A record that can't be parsed says nothing of which routes are whose, so it owns nothing: its routes count as foreign, which no owner removes or changes, and routetable's layout already goes around foreign identities (`Survey.Held`, halves), so connecting works. No route is removed on a guess (the ticket's second option, "remove only routes that match a parsed record", has no parsed record to match).
- Corrupt means: no boot line, a line after it that isn't an identity, not a regular file (a fifo, a directory, a socket: trusteddir looks before it opens, since a socket can't be opened), or a symlink (ELOOP). Any other read failure (EACCES, EIO) stays a hard error, as TP-108 made it: nothing is set aside on a failed read.
- Own record: set aside at start, under the owner's lock (already held), renamed `<owner>.routes.corrupt-<boot session>` in the same directory (`trusteddir.Rename`), replacing an earlier one of the same owner and boot; an earlier entry of the other kind (a file or an empty directory) that renameat(2) won't replace is removed first, a non-empty directory there stays and the owner fails to start (documented). At the same start the owner removes its set-aside records of earlier boots; what it can't list or remove stays, never failing the start.
- Another owner's corrupt record is reported in place and never touched: no lock is taken, nothing is moved (round 1 removed the cross-owner set-aside: it made `ErrBusy` lie and, with the agent opening the overlay before the route table, never ran). Its routes count as foreign for that survey; its owner sets it aside at its next start, or rewrites it at its next change.
- This owner's own routes in `thinkpolRoutes` come from memory (`c.owned`), not a re-read of its own record: the record is a copy of it, read only at start, and a corrupt copy must not make our own routes look foreign.
- Health follows the leftovers, not the file. `Survey.CorruptRecords` lists this boot's corrupt records, set aside or another owner's in place, each with why and its mtime (a stat each; a failed stat still reports, a survey never fails on reporting); one last written before this boot (mtime before `kern.boottime`) whose content proves nothing of its boot (no boot line, not a regular file, a symlink) goes unreported, since what it named went with that boot, and leaves no trace but the file; one whose boot line names this boot is reported whatever its mtime (round 2). A set-aside file someone made valid since is reported as "set aside; reads clean now". `Survey.UnownedRoutes` counts the routes with routeFlag that no record names. routetable copies both (`Status.CorruptRecords`, `Status.UnownedRoutes`) and warns of each record, naming it and saying why: once while surveys find it unchanged, again when it comes back after a survey without it or with a new reason or mtime (round 2); the agent reports `route_records_corrupt` (degraded) only while both are nonzero (unowned routes alone may be another program's that uses the same flag), the local API counters `route_table.corrupt_records` and `route_table.unowned_routes`, and `thinkpol status` prints a `route records:` line whenever a corrupt record is seen, whether or not the route table holds routes. The problem code is plural like its counted siblings (`policy_rules_ahead`, `overlay_routes_ahead`) and the counter: it covers any number of records.
- The supervisor has no darwin configurator, so a corrupt `supervisor.routes` on a Mac is never set aside: it is reported in place until someone removes it or the Mac reboots (documented in `netcfg/doc.go`). Chosen over skipping that owner on darwin: only a person makes one on a Mac and the report says where; skipping would also turn a valid one's routes from thinkpol's to foreign, out of this ticket's scope.
- One record can be counted twice in one survey, until the next: read in place, then set aside by its owner's start before the survey stats the set-aside name (a comment in `Survey`); the other order would miss it.
- In the in-place case (a running owner's record corrupted, no set-aside file) the owner still removes its own routes, from memory, and rewrites the record at its next change. What decides it is whether the owner was already running when its record went bad, not whether it runs now: a set-aside record's owner restarted owning nothing, so that record's routes stay. The user-facing text says "an owner already running when its record went bad still removes its own; the rest stay until reboot, unless they went with their owner's interface" (round 3; the overlay's routes go with its utun, the route table's rejects and direct routes don't).
- The cost: a crashed run's routes that the corrupt record named stay until reboot (RR53): a leftover host route to an old endpoint sends that address direct (counted as `policy_rules_ahead`), leftover reject routes keep IPv6 and the overlay range blocked after disconnecting. `thinkpol diag` lists them as unrecorded RTF_PROTO2 routes. Removing the set-aside file acknowledges the problem (health clears), it doesn't repair it: the routes stay.

**Device checklist (for TP-144's re-run).** On the Mac, the agent running as the service.

1. A running owner's record corrupted (the overlay's, in place: the degraded case).
   - Do:
     ```sh
     thinkpol connect
     printf 'garbage\n' | sudo tee /private/var/db/thinkpol/netcfg/overlay.routes >/dev/null
     sleep 70
     thinkpol status
     sudo thinkpol logs | grep 'corrupt route record'
     ```
   - What happens: the route table's next survey (the one-minute backstop, or a routing change) reads the overlay's record as corrupt: it holds nothing, the overlay's routes look foreign and unowned. Nothing moves the file.
   - Expect: `status` has `route_records_corrupt` among the health problems, health degraded, and neither `policy_rules_ahead` nor `overlay_routes_ahead`: the overlay's routes (its halves into the TUN) look foreign to the route table, but they are no host routes, so nothing counts as ahead (`TestAnOverlaysRoutesSeenAsForeignAreNothingAhead`). The line `route records: 1 corrupt (see the log for which and why); N thinkpol routes no record names (an owner already running when its record went bad still removes its own; the rest stay until reboot, unless they went with their owner's interface)` (`1 thinkpol route no record names (an owner already running when its record went bad still removes its own; otherwise it stays until reboot, unless it went with its owner's interface)` for one); the log has `route table: a corrupt route record holds no routes; the routes it named count as foreign here ...` with `record=/private/var/db/thinkpol/netcfg/overlay.routes` and `reason=` naming the bad line. If the overlay re-applies meanwhile (a map change), it rewrites the record and the line goes.
   - Do:
     ```sh
     thinkpol disconnect
     sudo ls -l /private/var/db/thinkpol/netcfg/
     ```
   - Expect: the overlay removes its routes from memory and its record with them: no `overlay.routes` is left.
2. Another owner's corrupt record at start (the overlay's, disconnected).
   - Do:
     ```sh
     printf 'garbage\n' | sudo tee /private/var/db/thinkpol/netcfg/overlay.routes >/dev/null
     thinkpol connect
     thinkpol status
     sudo thinkpol logs | grep 'corrupt route record'
     sudo ls -l /private/var/db/thinkpol/netcfg/
     ```
   - What happens: the overlay's configurator finds its record corrupt at start and renames it; the route table's survey reports the set-aside file and warns once. No route of it is left, so health stays clear.
   - Expect: `connect` succeeds; `status` has no `route_records_corrupt` and the line `route records: 1 corrupt (see the log for which and why); no route left that no record names`; the log has the warn with `record=/private/var/db/thinkpol/netcfg/overlay.routes.corrupt-<uuid>` and `reason=` saying line 1 is no boot line; the listing has that file (its content `garbage`) and a fresh `overlay.routes` starting with the header and a `boot` line.
3. The route table's own corrupt record.
   - Do:
     ```sh
     thinkpol disconnect
     printf 'garbage\n' | sudo tee /private/var/db/thinkpol/netcfg/route-table.routes >/dev/null
     thinkpol connect
     thinkpol status
     sudo thinkpol logs | grep 'corrupt route record'
     sudo ls -l /private/var/db/thinkpol/netcfg/
     ```
   - What happens: the route table's configurator sets its own record aside at start and enforces the routes as usual.
   - Expect: `connect` succeeds, the route table is enforced (`route table: N routes`); `status` says `route records: 2 corrupt ...; no route left that no record names`, no `route_records_corrupt`; a new warn names `route-table.routes.corrupt-<uuid>`; that file exists.
4. Clean up.
   - Do:
     ```sh
     sudo sh -c 'rm /private/var/db/thinkpol/netcfg/*.routes.corrupt-*'
     thinkpol disconnect
     thinkpol connect
     thinkpol status
     ```
   - What happens: no corrupt record is left for this boot. Removing the files is an acknowledgement, not a repair: routes a corrupt record named would stay until reboot (none are left here). After a reboot each owner's first start removes its set-aside files of earlier boots anyway.
   - Expect: `status` has no `route records:` line and no `route_records_corrupt`.

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
- 2026-10-24 docs: in the before-M2 list (TP-108 made a foreign corrupt record a hard connect failure)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp124
- 2026-10-28 corrupt route records are set aside (`<owner>.routes.corrupt-<boot>`) instead of failing: the owner's own at start, another owner's during a survey under its lock; their routes count as foreign and are never removed; `Survey.SetAside` → routetable `Status.RecordsSetAside` (warned once per file, naming it) → health `route_record_set_aside` (degraded), counter `route_table.records_set_aside`, a `thinkpol status` line; `trusteddir.Rename`; docs: netcfg, routetable, trusteddir and agent package docs, routing.md, RESIDUAL-RISKS RR53 (new). Decisions in Notes
- 2026-10-28 tests: `TestACorruptRecordOfAnotherOwnerIsSetAside`, `TestACorruptRecordOfARunningOwnerIsLeftToIt`, `TestAnUnreadableRecordFailsTheSurvey`, `TestTheOwnersCorruptRecordIsSetAsideAtStart`, `TestRecordsRoundTrip` (corrupt classification, a symlink), `TestRenameStaysInTheDirectory`, `TestASetAsideRecordIsCountedAndWarnedOnce`, `TestRouteTableCountsReachTheEngine`, `TestHealth` (new case), `TestASetAsideRecordReachesStatusAndCLI`; TP-108's `TestACorruptRecordOfAnotherOwnerFailsTheSurveyAndDefaultRoute` replaced
- 2026-10-28 mutations, each caught by a failing test: another owner's corrupt record an error again; a running owner's record set aside; the own record's set-aside skipped; the own set-aside guessing an identity; `SetAside` never reported; a symlink not corrupt; every read failure corrupt; own routes not counted as thinkpol; `Rename` as a link (no replace); routetable warning on every survey, its count sticking, no note at all; the engine not copying the count; no health problem; no status line; no counter
- 2026-10-28 not tested: the re-read under another owner's lock (a configurator of it replacing the record between the first read and the lock) has no seam without a test hook; not verified on a device: the set-aside through the real routing socket and the service's connect (TP-144's re-run, checklist in Notes)
- 2026-10-28 `make lint` and `make test` exit 0 on ffca479; `make lab-test` (`LAB_P=1`, other labs up; `GOFLAGS=-p=4`) exit 0 on ffca479 with `gotest: ok, 36 packages`
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.14)
- 2026-10-28 has-errors → in-progress
- 2026-10-28 round 1 fixes (R1.1–R1.14): another owner's corrupt record is reported in place, never locked or moved (its owner sets it aside at its own start); the acceptance wording changed from "the record is set aside" to "reported in place, its routes Held; its owner sets it aside at start". `Survey.SetAside` → `Survey.CorruptRecords` (path and why) plus `Survey.UnownedRoutes` (routeFlag routes no record names) → routetable `Status.CorruptRecords`/`UnownedRoutes` (warned once per record with its reason) → health `route_records_corrupt` (degraded) only while both are nonzero, counters `route_table.corrupt_records` and `route_table.unowned_routes`, a `route records:` status line outside the routes block; earlier boots' set-aside records removed at the owner's start; a corrupt record older than `kern.boottime` set aside but unreported; a set-aside entry of the other kind removed before the rename; reporting never fails a survey; docs: netcfg (symlink in the definition, no ticket id, Survey doc), record and `owned`/`thinkpolRoutes` comments, trusteddir `Rename`, routetable and agent docs, RR53. Notes' decision and device checklist rewritten (checklist step 4: removing the file acknowledges, doesn't repair)
- 2026-10-28 tests: `TestACorruptRecordOfAnotherOwnerIsReportedInPlace` (replaces `TestACorruptRecordOfAnotherOwnerIsSetAside`; DefaultRoute now meets the corrupt file), `TestAnEarlierBootsSetAsideRecordIsNotReported`, `TestTheOwnerRemovesEarlierBootsSetAsideRecordsAtStart`, `TestACorruptRecordFromBeforeThisBootIsNotReported`, `TestASetAsideRecordReplacesAnEarlierOneOfTheOtherKind`, `TestACorruptRecordIsCountedAndWarnedOnce`, `TestACorruptRecordReachesStatusAndCLI`, `TestHealth` (three cases), `TestRouteTableCountsReachTheEngine`; `TestACorruptRecordOfARunningOwnerIsLeftToIt` dropped (one case now)
- 2026-10-28 mutations, each caught by a failing test: another owner's record set aside again in `recordOf`; another owner's corrupt record an error again (DefaultRoute fails); another owner's corrupt record not reported; no reason; `UnownedRoutes` never counted, or counting our own routes; the boot dropped from `setAsideName`; `clearSetAside` not called, removing this boot's, removing other owners', not removing directories; no mtime check; no remove-and-retry on the rename; health on the record alone, on unowned routes alone; the engine not copying `UnownedRoutes`; routetable not copying it, warning without the reason, warning on every survey; the status line back under the routes block; either counter missing; the leftover count missing from the line
- 2026-10-28 not tested: a failed stat while reporting (still reported, R1.5) has no seam in a directory the test can read; the mtime check uses the host's `kern.boottime` (read only). Not verified on a device: the in-place report, the set-aside through the real routing socket and the service's connect (TP-144's re-run, checklist in Notes)
- 2026-10-28 cross-family review (Cursor, round 1, verdict merge) concurred: its two findings, the symlink missing from the doc and the status line nested under the routes block, are R1.4 and R1.14
- 2026-10-28 takeover after the previous fixer stopped at 235a313: re-read the branch diff against every finding; the agent side (status, health, render) was already done in 724998a; merged origin/rewrite (TP-138)
- 2026-10-28 `make lint` and `make test` exit 0 on the merge c2ef087 (code unchanged in 1e2d427); `make lab-test` (`LAB_P=1`, other labs up; `GOFLAGS=-p=4`) exit 0 on 1e2d427 with `gotest: ok, 36 packages`
- 2026-10-28 in-progress → review
- 2026-10-29 review → has-errors (round 2: R2.1–R2.10)
- 2026-10-29 has-errors → in-progress
- 2026-10-29 round 2 fixes (R2.1–R2.10): the in-place case's copy (render.go status line, singular "1 thinkpol route", "see the log for which and why"; the routetable warn; `status.go` problem doc; `dataplane/routetable.go`; `netcfg.go`; `netcfg/doc.go`; `routetable/doc.go`; `agent/doc.go`; RR53; routing.md) says "a running owner still removes its own; a dead one's stay until reboot" and "a set-aside file"; checklist step 1 expects `route_records_corrupt` (degraded) and neither `policy_rules_ahead` nor `overlay_routes_ahead` (verified: the overlay's halves into the TUN are no host routes, so nothing counts as ahead; checklist steps 2–3 strings updated too). routetable keeps only what the last survey found, keyed on path, reason and mtime (`netcfg.CorruptRecord.Modified`, new). trusteddir's `openRegular` looks (fstatat, NOFOLLOW) before it opens, so a socket is `ErrNotRegular` (corrupt), not EOPNOTSUPP. The mtime gate applies only to content that proves nothing of its boot; one whose boot line names this boot is reported whatever its mtime. A comment on the transient double count in `Survey`. A corrupt `supervisor.routes` on darwin is documented as never set aside (chosen over skipping the owner: see Notes). `trusteddir.Names` and `trusteddir.RemoveEntry` replace the raw directory work in `record_darwin.go`; `Rename`'s doc lists EEXIST (kept in the retry). A set-aside file that now parses reports "set aside; reads clean now"
- 2026-10-29 tests: `TestRecordsRoundTrip` (a socket), `TestACorruptRecordOfThisBootIsReportedWhateverItsMtime`, `TestASetAsideRecordThatReadsCleanNowStillSaysWhy`, `TestANonEmptyDirectoryAtTheSetAsideNameFailsTheStart`, `TestTheOwnerRemovesEarlierBootsSetAsideRecordsAtStart` (a symlink and a non-empty directory at earlier boots' names), `TestACorruptRecordOfAnotherOwnerIsReportedInPlace` (Modified), `TestASocketIsRefused`, `TestEntriesAreListedAndRemovedInTheDirectory` (trusteddir), `TestACorruptRecordIsCountedAndWarnedOnceWhileUnchanged` (renamed; report, clear, report again, a new reason, a new mtime), `TestAnOverlaysRoutesSeenAsForeignAreNothingAhead`, `TestACorruptRecordReachesStatusAndCLI` (new strings, singular and plural)
- 2026-10-29 mutations, each caught by a failing test: no fstatat before the open (socket, netcfg and trusteddir); the mtime gate without the this-boot exception; an empty Reason for a clean set-aside file; Modified off by a second; `clearSetAside` with `os.RemoveAll`; `clearSetAside` following a symlink to its target; `setAside` clearing the target with `os.RemoveAll`; `RemoveEntry` not removing directories; `Names` reading dir's own descriptor (offset spent: the second call lists nothing); the warn key without the reason, without the mtime; `corruptWarned` never pruned (the old behaviour fails too); a warn on every survey; the singular status line plural; the old "stay until reboot" string. `TestAnOverlaysRoutesSeenAsForeignAreNothingAhead` survives each single mutant tried (the TUN skip in `shadowForeign` dropped; `cover` or `shadow` counting non-host routes; Held not taken): the property is held twice over, by the TUN skip and by counting only host routes. A double mutant (routes into the TUN shadowed and the overlay's ranges counted ahead) is caught
- 2026-10-29 merged origin/rewrite (d8d14ee, board only); `make lint` and `make test` exit 0 on 514f55c (code unchanged by the merge 387bbb1); `make lab-test` (`LAB_P=4`, no other labs; `GOFLAGS=-p=4`) exit 0 on 387bbb1 with `gotest: ok, 36 packages`
- 2026-10-29 not verified on a device: the in-place warn and status line, the socket case on a real `/private/var/db` and the service's connect (TP-144's re-run, checklist in Notes). Out of scope, for the orchestrator: on darwin a valid `supervisor.routes` (which only a person can write there) is still trusted as thinkpol's
- 2026-10-29 in-progress → review
