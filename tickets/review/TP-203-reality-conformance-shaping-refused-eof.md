---
id: TP-203
title: "reality conformance: ShapingRefused fails with 'TLS handshake: EOF'"
milestone: M2
area: dataplane/transport
stream: transports
repo: thinkpol-vpn
size: M
depends_on: [TP-087]
refs: [C6, docs/design/transports.md#transports]
owner: "agent-tp-203"
branch: "tp-203-reality-conformance-shaping-refused-eof"
---

## Goal
TP-087's reality conformance test passes every time, or the product bug it exposes is fixed.

## Scope
- Find the root cause of TestConformanceShaped/random/ShapingRefused (and the earlier spelling TestConformance/ShapingRefused/2) failing with "TLS handshake: EOF": about 1 in 3 when its package runs alone in a lab node (`make lab-gotest`), seen by TP-026's implementer on 2026-11-12 and by TP-087's merge on 2026-11-09.
- Fix whichever is wrong, the test or the product. No retries, raised timeouts or skips unless the evidence shows the test's timing assumption is the only wrong thing.

## Out of scope
- Anything beyond the reality package, its tests and the conformance suite they run (transporttest); reality behind the shared listener is TP-201.

## Acceptance
- [x] root cause named with evidence (a failing run explained, not guessed)
- [x] fix (test or product, whichever is wrong; if it's the product, what a real client would see is written down)
- [x] the package passes 20 consecutive runs in a lab node
- [x] every new or changed test mutation-checked

## Notes
- **Root cause (2026-11-12): the suite, not the product.** The failing line, `transporttest.go:1235` on rewrite 567b481 (TP-201's full lab log: `TestConformanceShaped/random/ShapingRefused/5 (0.33s) transporttest.go:1235: dial …: reality: TLS handshake: EOF`), is `e.connectAdmitted(fixed)`: the test sets a table that admits `fixed`, then dials at once. Listeners take a table change in the background (reality's `watch` goroutine), which the suite allows. A hello that arrives before the listener has the new table fails authentication and goes to the suite's camouflage (the `Recorder`, which closes the connection), so reality's dial itself fails with EOF mid-handshake. `connectAdmitted` was written to dial again in that window, but only for a dial that returns a link the listener never accepts (udp); a failed dial went through `e.dial`, which fails the test. With a 0.33 s subtest the failure was the first dial after the table change.
- **Evidence.** In an idle lab node the listener applies the table 37 µs to 1.2 ms after `Set` (median 156 µs, 330 samples) and no hello lost the race in 25 iterations of `RUN=TestConformance` (825 ShapingRefused subtests); a dial on loopback takes about as long, so a loaded node (a full lab) can let the hello win. Made deterministic by a peer table whose snapshot lags 5 ms (`lateTable`): on the old `connectAdmitted`, 22 of 22 `TestConformance/ShapingRefused` subtests failed in a lab node with the reported message at the same call, the temporary log showing the order: the fixed peer's short id not in the listener's table, its dial failing 53 µs later with EOF, the listener applying the table holding it 4.9 ms after that.
- **What a real client sees** (unchanged, not a bug): a client whose short id a new map just added and that dials before its entry node took the map is treated like any unauthenticated hello. Without a camouflage it is spliced to the target, its dial fails with ErrNotAuthenticated, and it dials again. Refusing in that window is the safe direction (the opposite, a revoked id still accepted, is RevocationRacingDial's and closes with ErrRevoked). No race in the refusal path was found.
- **Fix.** `connectAdmitted` dials again after a failed dial too, waiting longer each time, within the same 5 s deadline; a listener that never takes the change still fails it with the dial's error. The reality `TestConformance` (unshaped) now runs on `lateTable`, so the window is exercised on every run; the shaped runs keep the immediate table. transport/doc.go says listeners may take a change in the background.
- **A second flake, found by the 20-run box (2026-11-12): `-count` reruns, not the product.** In the first lab run of 7, iteration 4 failed `TestListenFailsUnlessTheTargetsRecordsAreLearned/stalled` in 0.00 s ("detected the records of a target that never answers"). REALITY keeps what it detected per process, keyed by the target's IP:port, and `-count` reruns every test in one process: the stalled front had been given a loopback port an earlier target used, whose records were already learned, so `detect` returned at once. Not a product bug: a real Listen checks the target with its own TLS handshake (verifyTarget) before detect, and a stalled target fails there. Fix in the fixture: `newFront` takes only an address REALITY's store and our detections know nothing about (listenUnlearned), holding the others open until the test ends.

## Log
- 2026-11-12 created in backlog (the reality conformance flake blocks the full lab)
- 2026-11-12 backlog → in-progress, owner: agent-tp-203
- 2026-11-12 root cause found (Notes): connectAdmitted failed on a dial camouflaged before the listener took the table; reproduced deterministically with a 5 ms lagging table (22 of 22 failed in a lab node on the old code)
- 2026-11-12 fix: connectAdmitted dials again after a failed dial; reality TestConformance runs on lateTable; transport doc.go sentence on background table changes. Mutations: connectAdmitted failing on the dial error again: TestConformance/ShapingRefused fails 11 of 11 with "reality: TLS handshake: EOF"; the reality listener never taking a table change (watch's apply dropped): ShapingRefused/0 fails after the 5 s deadline with the dial's error; lateTable's lag removed: the old code passed 25 lab iterations, so the lag is what makes the window certain
- 2026-11-12 make test green; make lint green but for govulncheck: GO-2026-6859 in net/http of go1.26.10 (fixed in go1.26.11), on rewrite too, TP-202's toolchain bump
- 2026-11-12 lab node, whole reality package -count 7 on b02a127: 6 of 7 iterations passed; iteration 4 failed TestListenFailsUnlessTheTargetsRecordsAreLearned/stalled (0.00 s), every ShapingRefused passed: a -count artifact (Notes, second flake)
- 2026-11-12 fix: newFront listens through listenUnlearned. Mutation, with a temporary test that learns a target's records at an address, closes it and offers that address to a stalled front first: with the check, the front takes another address and detect fails as it should; check disabled: the front takes the learned address and detect returns in 0.01 s, "detected the records of a target that never answers" (the lab symptom). make test green; make lint green but for the same govulncheck finding
- 2026-11-12 lab node, whole reality package on a9fd476: 21 consecutive runs pass (make lab-gotest COUNT=7, three invocations back to back, LAB_P=1; no failure in any)
- 2026-11-12 acceptance boxes ticked: root cause and the second flake in Notes with their failing runs; fixes in transporttest's connectAdmitted and reality's test fixtures, no product change (a real client's view in Notes); 21 lab-node runs; mutations in the lines above
- 2026-11-12 lab: full make lab-test (GOFLAGS=-p=2, LAB_P=1, thinkpol-fulllab + docker + 3 CPU slots) green on e0e84c6: the lab package and all 38 node-phase packages, reality included
- 2026-11-12 not verified here: the original race in a natural failing run with the diagnostic log on (25 idle lab-node iterations never lost it; it is shown with the 5 ms lagging table and explained by TP-201's failing line); whether udp's and the supervisor's older ShapingRefused timeouts under load (TP-020 Notes) are the same window (their dials don't fail, so connectAdmitted already redialled for them); make lint's govulncheck finding GO-2026-6859 (go1.26.10 net/http) is on rewrite too and is TP-202's toolchain bump
- 2026-11-12 in-progress → review
