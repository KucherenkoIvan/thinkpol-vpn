---
id: TP-259
title: "Flaky internal/dataplane TestTheFirstInitiationSinceLinkUpIsFromTheNeighborsUpSince under load"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
internal/dataplane's TestTheFirstInitiationSinceLinkUpIsFromTheNeighborsUpSince failed once in `make test` and once in a targeted run of 20 under load (TP-252's runs, 2026-11-19); a second `make test` passed. Find the timing assumption it makes and fix it: watch state, don't lengthen a sleep.

## Scope
- Reproduce under load, name the timing assumption, fix the test (or the code, if the code is wrong).

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- Seen in TP-252's runs: once in `make test` under heavy load, once in a targeted `-count 20`. The package doesn't import lab/censor.

## Log
- 2026-11-19 created in backlog (TP-252 review)
