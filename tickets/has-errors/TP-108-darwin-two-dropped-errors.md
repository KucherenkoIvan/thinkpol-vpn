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
- netcfg: propagate errors from `readRecord` when building `thinkpolRoutes`, so a corrupt owner record does not make that owner's routes look foreign; the same wording for the owner's own record read at start; the record reader (`record_darwin.go`) is included.
- dns: propagate store errors from `otherResolvers` / `get`, so `Problem()` cannot report protected after a failed read; the resolver-directory read; the primary service's read (a failed read keeps the last upstreams, offline still clears them); the read-back after setting an override names its read failure.

## Out of scope
- Linux netcfg or DNS changes.
- Broader netcfg ledger consolidation (TP-102).

## Acceptance
- [x] fake-based unit tests for both failure paths — `TestACorruptRecordOfAnotherOwnerFailsTheSurveyAndDefaultRoute` (netcfg_darwin_test.go) writes a corrupt record of another owner and expects `Survey`/`DefaultRoute` to fail; `TestAFailedReadOfAnotherResolverIsReported` and `TestAFailedListingOfOtherResolversIsReported` (system_darwin_test.go) inject get/keys failures into the fake store and expect `Update` to fail and `Problem()` to report `ErrUnprotected`. Round 2 adds `TestAnUnreadableResolverDirectoryIsReported` and `TestAFailedPrimaryReadKeepsTheUpstreamsOfflineClearsThem` (system_darwin_test.go), and the corrupt-record test asserts the error names the record
- [x] `make lint`, `make test`, `make lab-test` pass — all three on commit bd66bf9 (round 1) and on 705605e (round 2); the round-2 lab run (`LAB_P=1`, `GOFLAGS=-p=4`, TP-105's lab sharing Docker) finished 2026-10-19 with `gotest: ok, 34 packages`

## Review findings
- [x] R2.1 BLOCKER: `TestAFailedListingOfOtherResolversIsReported` never reaches `otherResolvers`: `keysErr` fails every `keys` call, so `targets()` fails first. Make the fake fail per pattern (`keysErrs map[string]error`), name the DNS-state pattern in production code (`serviceDNSPattern` next to `serviceStatePattern`) and use it in both; the test fails only that pattern and asserts the error message names the listing ("listing the network services' DNS states"), so it can't pass on another error. Prove it: with the new keys check reverted, the test must fail. — fake fails per pattern, both places use `serviceDNSPattern`; with the keys check reverted the test fails (Update nil error, Problem nil), verified 2026-10-19 before restoring the check.
- [x] R2.2 `internal/dataplane/dns/system_darwin.go` ~440: `os.ReadDir(resolverDir)` drops its error. `fs.ErrNotExist` → empty (the normal case); any other error → returned, so `Problem()` reports unprotected. Test: point `resolverDir` at a regular file (ENOTDIR) → `Update` fails, `Problem()` is `ErrUnprotected`. — `TestAnUnreadableResolverDirectoryIsReported`.
- [x] R2.3 ~453-455 `primaryOriginal` drops `primaryServers`' error: one failed scutil read makes primary nil, `tell(nil)` runs, and the direct upstreams are wiped until the next good check — forever if the failure persists. On a read error keep `s.primary`, skip tell, and log once (Warn) with the error; "no primary network service" (offline) is a real empty answer and still tells — keep how `primaryServers` distinguishes the two. Test with the fakes: a failed read keeps the previous upstreams; offline still clears them. — the two are separated by the `errNoPrimary` sentinel; `TestAFailedPrimaryReadKeepsTheUpstreamsOfflineClearsThem`.
- [x] R2.4 ~363-364: the read-back after setting an override discards the read error's cause: report "dns: reading back <key>: <err>" when the read fails, "doesn't hold the override" only when it read and differs.
- [x] R2.5 `internal/dataplane/netcfg/netcfg_darwin.go` ~205: match ~816's wording: "netcfg: reading %v's route record: %w".
- [x] R2.6 `netcfg_darwin_test.go` ~782-787: assert the error names the record ("overlay's route record"), not just non-nil.
- [x] R2.7 Notes: a corrupt record of another owner fails this node's route-table survey until someone deletes the file under /private/var/db/thinkpol/netcfg (only root can write there; the error names the path); recovery belongs with TP-102. — written into Notes.
- [ ] R3.1 BLOCKER: `primaryServers`' IPv6 fallback (`system_darwin.go` ~614-618) drops the IPv6 global's read error, so a failed read on an IPv6-only network reads as "no primary network service" (offline) and wipes the direct upstreams. Return the error ("dns: reading State:/Network/Global/IPv6: …"); a missing IPv6 key stays "no primary". Test: the IPv4 global absent, the IPv6 global with a PrimaryService; fail the IPv6 get → no tell, one Warn across two checks; clear the error and remove the key → exactly one tell of nil. Remove the Notes paragraph that parked this.
- [ ] R3.2 `errNoPrimary` escapes from the exported `SystemUpstreams` (~658-661): an offline Mac now logs "the system's resolvers are unknown … dns: no primary network service". Return nil, nil for `errNoPrimary` there, as before this branch. Test: aMac without the IPv4 global → `systemUpstreams` returns nil, nil.
- [ ] R3.3 `scutil_darwin.go` `parseList` (~247-260): scutil reports a failed command as text and exits 0 (seen: `frobnicate: unknown, type "help" for command info`, exit 0), so today a failed list reads as an empty list. Accept only "  subKey [n] = <key>" lines as keys and "  no keys." (seen) as empty; any other non-blank line is an error. Real samples: "  subKey [0] = State:/Network/Global/DNS", "  no keys.", and for a missing key in show: "  No such key". Keep the existing fixtures passing; add tests for the error case.
- [ ] R3.4 `parseShow` (~278-281): accept a top-level "Key :" line (an empty string value, trimmed of its trailing space) as an empty string, the way arrays already handle "0 : ", instead of failing the whole read. Test with a fixture.
- [ ] R3.5 A primary read that keeps failing leaves stale upstreams with one Warn and nothing in status. Make it visible: while `primaryFailed` is set, `Problem()` (or the status the node reports) says the direct upstreams may be stale — the smallest honest place, not `ErrUnprotected` unless it is one; say in the Log why the place was picked.
- [ ] R3.6 `primaryOriginal`'s switch: simplify per the design reviewer (`if err != nil && !errors.Is(err, errNoPrimary) { warn once; keep; return s.primary }`; then reset the flag, nil for offline, else the read). Name the Setup DNS pattern (`serviceSetupDNSPattern`) and use it in both places. Test that the warning re-arms after a good read (two episodes → two Warns).
- [ ] R3.7 `netcfg/record_darwin.go`: an empty or comment-only record (no boot line) is corrupt, not empty ("%s: no boot session"); a Stat failure returns its error instead of "not a regular file". `netcfg_darwin_test.go` ~782 also checks the error names the path.

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

Safe behaviour chosen (per the ticket's goal, "fail closed"): a record that can't be read is an error, not an empty one — a missing record or one of an earlier boot still reads as empty, so only real corruption or a failed read errors. With another owner's identities unknown, `DefaultRoute` and `Survey` refuse to answer rather than mistake that owner's routes for foreign ones. Likewise a failed store read in `otherResolvers` leaves `others` at its previous value and fails `apply`, so `Problem()` reports `ErrUnprotected`. Not verified on a device: only the fakes (fake kernel, fake store) exercise this; real Darwin behaviour is for the owner's device run.

A corrupt record of another owner (the overlay's, say) keeps failing this node's route-table survey until someone deletes the file under /private/var/db/thinkpol/netcfg — only root can write there, and the error names the path. Recovery belongs with TP-102.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-108-darwin-two-dropped-errors
- 2026-10-19 in-progress → review — both fixes landed, fake-based tests added, make lint/test/lab-test pass (bd66bf9); not verified on real macOS hardware, only the fakes
- 2026-10-19 review → has-errors — round 2 findings R2.1–R2.7; scope widened to the whole class
- 2026-10-19 has-errors → in-progress — round 2 fixes start
- 2026-10-19 in-progress → review — all round 2 findings fixed and checked (705605e), make lint/test/lab-test pass, the full lab run finished 2026-10-19 (`gotest: ok, 34 packages`); still not verified on real macOS hardware, only the fakes
- 2026-10-19 review → has-errors — round 3 findings R3.1–R3.7
