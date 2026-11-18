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

## Log
- 2026-11-18 created in backlog (seen in lab runs 2026-11-17)
- 2026-11-18 backlog → in-progress, owner: agent-tp-244
