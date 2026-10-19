---
id: TP-108
title: "Darwin: two dropped errors"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-108-darwin-two-dropped-errors"
---

## Goal
Darwin netcfg and DNS adapters surface read failures instead of treating corrupt or unreadable state as empty or protected.

## Scope
Every place in `internal/dataplane/netcfg/netcfg_darwin.go` and `internal/dataplane/dns/system_darwin.go` where an unreadable answer is taken as empty — one ticket fixes the class, not single spots:
- netcfg: propagate errors from `readRecord` when building `thinkpolRoutes`, so a corrupt owner record does not make that owner's routes look foreign; the same wording for the owner's own record read at start.
- dns: propagate store errors from `otherResolvers` / `get`, so `Problem()` cannot report protected after a failed read; the resolver-directory read; the primary service's read (a failed read keeps the last upstreams, offline still clears them); the read-back after setting an override names its read failure.

## Out of scope
- Linux netcfg or DNS changes.
- Broader netcfg ledger consolidation (TP-102).

## Acceptance
- [x] fake-based unit tests for both failure paths — `TestACorruptRecordOfAnotherOwnerFailsTheSurveyAndDefaultRoute` (netcfg_darwin_test.go) writes a corrupt record of another owner and expects `Survey`/`DefaultRoute` to fail; `TestAFailedReadOfAnotherResolverIsReported` and `TestAFailedListingOfOtherResolversIsReported` (system_darwin_test.go) inject get/keys failures into the fake store and expect `Update` to fail and `Problem()` to report `ErrUnprotected`
- [x] `make lint`, `make test`, `make lab-test` pass — all three on commit bd66bf9; the lab run (`LAB_P=1`, shared Docker) finished 2026-10-19 with `gotest: ok, 34 packages`

## Review findings
- [x] R2.1 BLOCKER: `TestAFailedListingOfOtherResolversIsReported` never reaches `otherResolvers`: `keysErr` fails every `keys` call, so `targets()` fails first. Make the fake fail per pattern (`keysErrs map[string]error`), name the DNS-state pattern in production code (`serviceDNSPattern` next to `serviceStatePattern`) and use it in both; the test fails only that pattern and asserts the error message names the listing ("listing the network services' DNS states"), so it can't pass on another error. Prove it: with the new keys check reverted, the test must fail. — fake fails per pattern, both places use `serviceDNSPattern`; with the keys check reverted the test fails (Update nil error, Problem nil), verified 2026-10-19 before restoring the check.
- [x] R2.2 `internal/dataplane/dns/system_darwin.go` ~440: `os.ReadDir(resolverDir)` drops its error. `fs.ErrNotExist` → empty (the normal case); any other error → returned, so `Problem()` reports unprotected. Test: point `resolverDir` at a regular file (ENOTDIR) → `Update` fails, `Problem()` is `ErrUnprotected`. — `TestAnUnreadableResolverDirectoryIsReported`.
- [x] R2.3 ~453-455 `primaryOriginal` drops `primaryServers`' error: one failed scutil read makes primary nil, `tell(nil)` runs, and the direct upstreams are wiped until the next good check — forever if the failure persists. On a read error keep `s.primary`, skip tell, and log once (Warn) with the error; "no primary network service" (offline) is a real empty answer and still tells — keep how `primaryServers` distinguishes the two. Test with the fakes: a failed read keeps the previous upstreams; offline still clears them. — the two are separated by the `errNoPrimary` sentinel; `TestAFailedPrimaryReadKeepsTheUpstreamsOfflineClearsThem`.
- [x] R2.4 ~363-364: the read-back after setting an override discards the read error's cause: report "dns: reading back <key>: <err>" when the read fails, "doesn't hold the override" only when it read and differs.
- [x] R2.5 `internal/dataplane/netcfg/netcfg_darwin.go` ~205: match ~816's wording: "netcfg: reading %v's route record: %w".
- [x] R2.6 `netcfg_darwin_test.go` ~782-787: assert the error names the record ("overlay's route record"), not just non-nil.
- [x] R2.7 Notes: a corrupt record of another owner fails this node's route-table survey until someone deletes the file under /private/var/db/thinkpol/netcfg (only root can write there; the error names the path); recovery belongs with TP-102. — written into Notes.

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

Safe behaviour chosen (per the ticket's goal, "fail closed"): a record that can't be read is an error, not an empty one — a missing record or one of an earlier boot still reads as empty, so only real corruption or a failed read errors. With another owner's identities unknown, `DefaultRoute` and `Survey` refuse to answer rather than mistake that owner's routes for foreign ones. Likewise a failed store read in `otherResolvers` leaves `others` at its previous value and fails `apply`, so `Problem()` reports `ErrUnprotected`. Not verified on a device: only the fakes (fake kernel, fake store) exercise this; real Darwin behaviour is for the owner's device run.

A corrupt record of another owner (the overlay's, say) keeps failing this node's route-table survey until someone deletes the file under /private/var/db/thinkpol/netcfg — only root can write there, and the error names the path. Recovery belongs with TP-102.

Also noticed in round 2, not fixed here (wasn't in the findings): `primaryServers`' IPv6 fallback (`system_darwin.go`, the `State:/Network/Global/IPv6` read) drops that read's error, so a failed read there reads as "no primary network service" — offline — and wipes the direct upstreams, the same wipe R2.3 fixed for the IPv4 read.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-108-darwin-two-dropped-errors
- 2026-10-19 in-progress → review — both fixes landed, fake-based tests added, make lint/test/lab-test pass (bd66bf9); not verified on real macOS hardware, only the fakes
- 2026-10-19 review → has-errors — round 2 findings R2.1–R2.7; scope widened to the whole class
- 2026-10-19 has-errors → in-progress — round 2 fixes start
