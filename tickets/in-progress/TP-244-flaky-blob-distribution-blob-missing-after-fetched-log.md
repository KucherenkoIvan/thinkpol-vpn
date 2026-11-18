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
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- Root cause, a product bug: `blobs.Service.obtain` logged "blob fetched" before it called `Store.Save`. On a device the store is the state directory (`diskBlobs.Save`: a temporary file, fsync, rename, directory fsync, then the index the same way), so on a slow, loaded disk the line came seconds before the file was in place, and the test's `sha256sum` right after the line found nothing. Nothing else removes or renames the file in that window: the write is atomic, and pruning runs in the same goroutine after `obtain` returns.
- Evidence: TP-243's full lab at 3d2f04d8 failed at the first `sha256sum` after the line, "No such file or directory". On this branch, the old order plus a 3 s sleep at the top of `diskBlobs.Save` (a slow disk) fails `TestBlobDistribution` the same way, at the same check; the fixed order with the same sleep passes.
- Fix: save, then log (`internal/dataplane/blobs/service.go`), stated in the package doc. The lab test's second check after the line had a 30 s poll that hid the same race; it is now a single read, like the first.

## Log
- 2026-11-18 created in backlog (seen in lab runs 2026-11-17)
- 2026-11-18 backlog → in-progress, owner: agent-tp-244
