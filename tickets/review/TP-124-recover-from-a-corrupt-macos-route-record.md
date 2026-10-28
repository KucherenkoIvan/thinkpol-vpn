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
- [x] a unit test with a corrupt record of another owner: the survey succeeds, the record is set aside, no route of that owner is removed — `TestACorruptRecordOfAnotherOwnerIsSetAside` (netcfg_darwin_test.go): a crashed overlay's routes and a corrupt overlay record; the route table's `Survey` and `DefaultRoute` answer, the record is at `overlay.routes.corrupt-<boot>`, `Survey.SetAside` names it (on the next survey too), the overlay's routes are `Held` (foreign), and after the route table's Apply and Close the kernel holds the overlay's routes unchanged. `TestACorruptRecordOfARunningOwnerIsLeftToIt`: a running owner's corrupt record isn't moved, the survey still answers, the owner rewrites it at its next Apply. `TestAnUnreadableRecordFailsTheSurvey`: a record that can't be read (mode 0) still fails the survey, nothing set aside
- [x] the same for the node's own record at start — `TestTheOwnersCorruptRecordIsSetAsideAtStart`: a crashed route table's routes and its corrupt record; the next configurator starts owning nothing, the record is set aside and reported, the leftovers are `Held`, an Apply over them fails with ErrConflict, and Close leaves the kernel unchanged
- [x] `make lint`, `make test` pass — both exit 0 on the code commit; `make lab-test` too (Log)

## Notes
- From TP-077's residual-risks research (2026-10-22); TP-108 R2.7 handed recovery to TP-102, which didn't add it.
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, macOS): done before the M2 lanes start. TP-108 made another owner's corrupt route record a hard connect failure, with no recovery but deleting the file by hand. The 2026-10-24 macOS device run's corrupt-record step was inconclusive; TP-144's re-run checks it again.

**Decision: set aside, own nothing (2026-10-28).** A record that can't be parsed says nothing of which routes are whose, so it owns nothing: its routes count as foreign, which no owner removes or changes, and routetable's layout already goes around foreign identities (`Survey.Held`, halves), so connecting works. No route is removed on a guess (the ticket's second option, "remove only routes that match a parsed record", has no parsed record to match). The record is renamed `<owner>.routes.corrupt-<boot session>` in the same directory (`trusteddir.Rename`), replacing an earlier one of the same owner and boot.
- Corrupt means: no boot line, a line after it that isn't an identity, not a regular file (a fifo, a directory), or a symlink (ELOOP). Any other read failure (EACCES, EIO) stays a hard error, as TP-108 made it: nothing is set aside on a failed read.
- Own record: set aside at start, under the owner's lock (already held). Another owner's: set aside during `Survey`/`DefaultRoute` only if its lock can be taken (no configurator of it runs), and read again under the lock first. A running owner's corrupt record is left in place: its routes count as foreign for that survey, and the owner rewrites the record at its next change.
- This owner's own routes in `thinkpolRoutes` now come from memory (`c.owned`), not a re-read of its own record: the record is a copy of it, and a corrupt copy must not make our own routes look foreign.
- Health: `Survey.SetAside` lists the set-aside files of this boot (a stat per owner), so it is right whoever set the record aside (the overlay's configurator never surveys). routetable counts them (`Status.RecordsSetAside`) and warns once per file, naming it; the agent reports `route_record_set_aside` (degraded), the local API counter `route_table.records_set_aside`, and `thinkpol status` prints a line. It lasts for the boot, as long as the routes may, or until someone removes the file.
- The cost: a crashed run's routes that the corrupt record named stay until reboot (RR53, new): a leftover host route to an old endpoint sends that address direct (counted as `policy_rules_ahead`), leftover reject routes keep IPv6 and the overlay range blocked after disconnecting. `thinkpol diag` lists them as unrecorded RTF_PROTO2 routes.
- Brief lock contention: taking another owner's lock during a survey can make that owner's start fail with ErrBusy if it starts in the same instant; only while a corrupt record exists.

**Device checklist (for TP-144's re-run).** On the Mac, the agent running as the service, the device disconnected (no configurator holds a lock).

1. Another owner's corrupt record (the overlay's).
   - Do:
     ```sh
     thinkpol disconnect
     printf 'garbage\n' | sudo tee /private/var/db/thinkpol/netcfg/overlay.routes >/dev/null
     thinkpol connect
     thinkpol status
     sudo thinkpol logs | grep 'set aside'
     sudo ls -l /private/var/db/thinkpol/netcfg/
     ```
   - What happens: the overlay's configurator finds its record corrupt at start and renames it; the route table's survey sees the set-aside file and warns once.
   - Expect: `connect` succeeds; `status` shows health `degraded: route_record_set_aside` and the line `1 corrupt route records set aside; the routes they named stay until reboot`; the log has `route table: a corrupt route record was set aside ...` with `record=/private/var/db/thinkpol/netcfg/overlay.routes.corrupt-<uuid>`; the listing has that file (its content `garbage`) and a fresh `overlay.routes` starting with the header and a `boot` line.
2. The route table's own corrupt record.
   - Do:
     ```sh
     thinkpol disconnect
     printf 'garbage\n' | sudo tee /private/var/db/thinkpol/netcfg/route-table.routes >/dev/null
     thinkpol connect
     thinkpol status
     sudo thinkpol logs | grep 'set aside'
     sudo ls -l /private/var/db/thinkpol/netcfg/
     ```
   - What happens: the route table's configurator sets its own record aside at start and enforces the routes as usual.
   - Expect: `connect` succeeds, the route table is enforced (`route table: N routes`); `status` says `2 corrupt route records set aside`; a new warn names `route-table.routes.corrupt-<uuid>`; that file exists.
3. Clean up.
   - Do:
     ```sh
     sudo sh -c 'rm /private/var/db/thinkpol/netcfg/*.routes.corrupt-*'
     thinkpol disconnect
     thinkpol connect
     thinkpol status
     ```
   - What happens: no set-aside file is left for this boot.
   - Expect: health has no `route_record_set_aside` and `status` has no set-aside line.

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
