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
owner: "agent-tp-242"
branch: "tp-242-fewer-containers"
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
- **Counts re-checked on rewrite bdcebaa4** (after TP-200, TP-238, TP-240): 26 lab tests started a `lab.Standard()` or `lab.Upstream()` lab outside the matrix (TestM0 twice, one per subtest), 5 more a hand-written 4-node topology (router, device-a, server-1, internet), and the harness has 9 lab-starting self-tests, not 8: TestLabStartsOverlapOnDistinctSubnets (TP-229) is one too.
- **`Only`** (lab/topology.go): `Standard().Only(names…)` keeps the named nodes and the networks they are on, and panics on a name the topology lacks, so a typo can't drop a node silently. A node's gateway must be kept (Validate).
- **Trimmed tests** (nodes before → after, what went). No dropped node was named, addressed or started anything in its test: each was an idle container. Where `newM0Space`'s builder was internet and internet had no other part, the router builds instead: the builder only runs `thinkpol dev keygen` / `map build` / `lists build` under /tmp/m0, and the host reads the files back, so which node builds is no part of any claim.
  - Censor and capture, device-a → server-1 through the router (6 → 3; device-b, server-2, internet out): TestCensorForwardsWhatNoModuleDecides, TestCensorFragmentedUDPBlocked ("nothing reaches server-1": server-1 stays), TestTCPResetReachesClient, TestTCPThroughCensorDrop, TestFullyEncryptedRandomNotHTTPS, TestTCPResetReachesBothEnds, TestCensorReplaysClientHello, TestCaptureFlagsRawWireGuard, TestShapingCapture.
  - Upstream, prober and server-hello (7 → 4; device-b, server-2, internet out): TestProberTellsEchoFromNginx, TestServerHelloAgainstTheSite. TestCensorSeesUpstream (7 → 3: router, server-1, camouflage; no device takes part).
  - Space tests with the router as builder: TestDiagShowsWhatTheHostHolds (6 → 3; its domestic list is built on the router), TestHealthWithNoLinkUp (6 → 3), TestTheCLIExitsBySysexits (6 → 3: router, device-b, server-1), TestLocalAPI and TestUpRunsTheM0Space (6 → 4: device-b stays, both drive it), TestM0/underlay-ipv4 and /underlay-ipv6 (6 → 4 each), TestIngressOffAdmitsOnlyServers (6 → 5, internet out; server-2 and device-b are its claim), TestServiceUnderSystemd, TestServiceUninstallAfterAServerCrash, TestTheNodeFileSetsUp (4 → 3, internet out).
  - TestTheCLIExitsBySysexits and TestDiagShowsWhatTheHostHolds pointed systemd-resolved at internet's address, where nothing answered and no name is looked up; they now point it at the router's servers-side address, as unanswered.
  - Internet stays where it is a resolver, a target or the foreign side: TestASecondAgentChangesNothing (6 → 5, server-2 out), TestDNSFollowsTheRules (6 → 5, server-2 out), TestDNSFollowsTheRulesOnAServerExit (6 → 4, device-b and server-2 out), TestDisconnectLeavesNothingBehind (6 → 5, server-2 out), TestEgressThroughAnExit, TestHealthWithAnExitThatNeverHandshakes, TestBlobDistribution (6 → 5, device-b out), TestNoIPv6LeavesAroundTheTunnel (7 → 5, device-b and server-2 out; internet and abroad, the two sides it checks nothing leaks to, stay), TestRouteTableSendsOnlyDirectAroundTheTunnel (8 → 6, same two out), TestSmoke (6 → 3: router, device-a, internet; its "nothing else routes" checks those three).
  - Not trimmed: TestKillSwitchUnderSystemd and TestRollbackPutsTheHostBack… (4 nodes; internet is the foreign destination traffic must or mustn't reach), TestRealityStockXray (1 node and Xray's container), the harness tests (their topologies are what they test), the matrix rows (TP-236's).
- **Single-node candidates**: neither moves into the node phase. TestTheCLIExitsBySysexits checks that `connect` exits 1 with device-b connected to server-1 (state connected, DNS not protected), and TestTheNodeFileSetsUp reads device-a's overlay MTU once it is connected to server-1: each needs a server and the router between. Both were trimmed to 3 nodes instead. No other lab test starts a single node it alone drives except TestRealityStockXray, which starts a stock Xray container beside it.
- **Harness self-tests** take the `TestHarness` prefix (9 tests: smoke_test.go 3, teardown_lab_test.go 3, subnets_lab_test.go 2, bindir_lab_test.go 1). `make lab-harness` runs them; `make lab-test`'s `lab/` phase skips them and a third phase, `lab-harness-cached`, runs `make lab-harness` unless a stamp named by the harness hash exists. TP-243's lab/testcache has not merged, so this is the small stamp: `$(LAB_HARNESS_CACHE)/<hash>` (default ~/.cache/thinkpol-lab/harness), written only after a pass. The hash (`make lab-harness-hash`) covers every non-test Go file under lab/ (subpackages too), lab/Dockerfile, lab/seccomp.json, the files holding `func TestHarness…`, and the Go and Docker versions; a failed version read fails the phase rather than hashing nothing.
- **Start budget**: lab.Start's 10 minutes used to start before the lab slot wait, so a lab queued behind others failed "setup" without starting. Now `labBudget` (lab/lab.go) gives the slot wait its own bound (45 min, under LAB_TIMEOUT's 60) and the start 10 minutes for the part before the slot (leftover removal, binaries) and 10 more from when the slot is held (`startBudget.waitThenStart`).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-18 backlog → in-progress, owner: agent-tp-242
