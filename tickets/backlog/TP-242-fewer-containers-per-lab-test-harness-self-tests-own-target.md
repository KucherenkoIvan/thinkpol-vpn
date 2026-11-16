---
id: TP-242
title: "Fewer containers per lab test; the harness's self-tests get their own target"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-229]
refs: []
owner: ""
branch: ""
---

## Goal
Each lab has only the nodes its test drives. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-16: a clean full lab takes 2823 s, and the remote runner's Docker starts only ~18–20 containers a minute, while a run starts 836 containers: the censor matrix 574 of them in 90 labs, each cell in use only 5–30 s.

## Scope
- Tests declare trimmed topologies; 25 tests use `lab.Standard()` (6 nodes) today.
- The 8 lab-harness self-tests move to `make lab-harness`, run when `lab/*.go` (non-test) changes and cached by that hash: TestLabsAreIsolated, TestAnotherRun…, TestIPv4OnlyNetwork, TestCommandStartsSealed, TestDownRefuses…, TestLabsBelongToTheirCheckout, TestDownRunRemovesOnlyItsRun, TestUsedSubnetsSurvives….
- Lab tests that only need one root node (candidates: TestTheCLIExitsBySysexits, TestTheNodeFileSetsUp; confirm each) move into the node phase as in-node tests.

## Out of scope

## Acceptance
- [ ] Container starts of the non-matrix lab phase ≤ 170. Evidence: the budget report.
- [ ] `make lab-harness` passes, and is run by any change under `lab/` non-test files. Evidence: the Makefile rule and a log.

## Notes
- Saving: ~50–70 starts ≈ 3–4 min.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
