---
id: TP-244
title: "Flaky TestBlobDistribution: the blob is missing right after the node logs it fetched"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-244"
branch: "tp-244-blob-distribution-flake"
---

## Goal
In two or three lab runs (TP-229's and TP-238's, 2026-11-17) TestBlobDistribution failed because the blob file wasn't on disk on device-a right after its node logged "blob fetched". Find whether the log line comes before the file is in place (a write or rename not finished, a different path, a cleanup), and fix the cause or the test's wait.

## Scope
- Reproduce, name why the file is missing after the log line, and fix the cause or the test's wait.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- Root cause, a product bug: `blobs.Service.obtain` logged "blob fetched" before it called `Store.Save`. On a device the store is the state directory (`diskBlobs.Save`: a temporary file, fsync, rename, directory fsync, then the index the same way), so on a slow, loaded disk the line came seconds before the file was in place, and the test's `sha256sum` right after the line found nothing. Nothing else removes or renames the file in that window: the write is atomic, and pruning runs in the same goroutine after `obtain` returns.
- Evidence: TP-243's full lab at 3d2f04d8 failed at the first `sha256sum` after the line, "No such file or directory". On this branch, the old order plus a 3 s sleep at the top of `diskBlobs.Save` (a slow disk) fails `TestBlobDistribution` the same way, at the same check; the fixed order with the same sleep passes.
- Fix: save, then log (`internal/dataplane/blobs/service.go`), stated in the package doc. The lab test's second check after the line had a 30 s poll that hid the same race; it is now a single read, like the first.

## Review findings
- [x] R1.1 (nit) The new unit test copied startNode's body by hand (no device log, Info level, no "log of …" dump on failure). Done: startNode takes optional handler wrappers (`wrap ...func(slog.Handler) slog.Handler`, internal/dataplane/blobs/service_test.go:207); TestAFetchedBlobIsInTheStoreWhenItsFetchIsLogged starts the device with it, so its log is dumped if it fails.
- [x] R1.2 (nit) A failed Save warned "storing a blob" with no kind or name and still logged "blob fetched", so a lab reader saw "No such file" without knowing why. Done: the Warn carries kind and name and "blob fetched" carries `stored` (true/false), save still before the log (internal/dataplane/blobs/service.go:730-738); doc.go:68-70 says so.
- [x] R1.3 (nit) Comments: onRecord's (service_test.go:298) reworded; the test's comment (service_test.go:317) no longer names the ticket.

## Log
- 2026-11-18 created in backlog (seen in lab runs 2026-11-17)
- 2026-11-18 backlog → in-progress, owner: agent-tp-244
- 2026-11-18 root cause: "blob fetched" was logged before `Store.Save` (product bug); fix: save, then log (blobs/service.go), package doc says so; lab test reads the file right after the line, its 30 s poll on the second check removed
- 2026-11-18 unit test TestAFetchedBlobIsInTheStoreWhenItsFetchIsLogged: passes 50 runs with -race; mutation: service.go's old order (log before save) restored, fails 5 of 5
- 2026-11-18 lab repro: old order plus a 3 s sleep at the top of `diskBlobs.Save` fails TestBlobDistribution at the first sha256sum, "No such file or directory", as in the full lab; the fix with the same sleep passes (345 s); neither change committed
- 2026-11-18 20 runs of TestBlobDistribution under load (other tickets' labs running) at f127d7ed: 20 pass, 0 fail; the COUNT=20 run was killed at its 60 min budget after 16 passes (runs took 42–409 s under load), the remaining 4 in a COUNT=4 run
- 2026-11-18 make lint, make test green at f127d7ed
- 2026-11-18 full `make lab-test` at 890b77e1 (before the orchestrator dropped the final full lab): EXIT 2 after 4050 s, every failure lab-slot starvation from concurrent full labs, not this change: 13 tests failed on "waiting for a free lab slot" or a `docker compose up` timeout, and `./lab` hit its 1 h budget with TestCensorMatrix and TestLabStartsOverlapOnDistinctSubnets still running; TestBlobDistribution passed; the 13 re-run targeted at 890b77e1 all pass (EXIT 0, 1030 s)
- 2026-11-18 merged origin/rewrite (TP-243) at 8b2e905e; there: make lint, make test green; lab-gotest TestBlobDistribution COUNT=3 pass (833 s), lab-gotest ./internal/dataplane/blobs/... pass; no full lab per the orchestrator's 2026-11-18 rule (targeted runs on the final commit, full labs on rewrite after merges)
- 2026-11-18 couldn't verify: a full lab green on this branch (the remote's lab slots were saturated); out of scope: the COUNT=20 lab-gotest can't finish 20 runs of a ~5 min test within lab-gotest's fixed 60 min `-timeout` under load
- 2026-11-18 in-progress → review
- 2026-11-18 review round 1: nits R1.1–R1.3, merge
- 2026-11-18 R1.1–R1.3 at 27365eb7: go test -race -count=20 ./internal/dataplane/blobs/ pass; make lint, make test green; lab-gotest TestBlobDistribution pass (122 s); mutation: the old order (log before save) fails TestAFetchedBlobIsInTheStoreWhenItsFetchIsLogged, with the device's log dumped
