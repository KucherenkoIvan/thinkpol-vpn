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
- `internal/dataplane/netcfg/netcfg_darwin.go` (~807): propagate errors from `readRecord` when building `thinkpolRoutes`, so a corrupt owner record does not make that owner's routes look foreign.
- `internal/dataplane/dns/system_darwin.go` (~413, ~419): propagate store errors from `otherResolvers` / `get`, so `Problem()` cannot report protected after a failed read.

## Out of scope
- Linux netcfg or DNS changes.
- Broader netcfg ledger consolidation (TP-102).

## Acceptance
- [x] fake-based unit tests for both failure paths — `TestACorruptRecordOfAnotherOwnerFailsTheSurveyAndDefaultRoute` (netcfg_darwin_test.go) writes a corrupt record of another owner and expects `Survey`/`DefaultRoute` to fail; `TestAFailedReadOfAnotherResolverIsReported` and `TestAFailedListingOfOtherResolversIsReported` (system_darwin_test.go) inject get/keys failures into the fake store and expect `Update` to fail and `Problem()` to report `ErrUnprotected`
- [x] `make lint`, `make test`, `make lab-test` pass — all three on commit bd66bf9; the lab run (`LAB_P=1`, shared Docker) finished 2026-10-19 with `gotest: ok, 34 packages`

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

Safe behaviour chosen (per the ticket's goal, "fail closed"): a record that can't be read is an error, not an empty one — a missing record or one of an earlier boot still reads as empty, so only real corruption or a failed read errors. With another owner's identities unknown, `DefaultRoute` and `Survey` refuse to answer rather than mistake that owner's routes for foreign ones. Likewise a failed store read in `otherResolvers` leaves `others` at its previous value and fails `apply`, so `Problem()` reports `ErrUnprotected`. Not verified on a device: only the fakes (fake kernel, fake store) exercise this; real Darwin behaviour is for the owner's device run.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-108-darwin-two-dropped-errors
- 2026-10-19 in-progress → review — both fixes landed, fake-based tests added, make lint/test/lab-test pass (bd66bf9); not verified on real macOS hardware, only the fakes
