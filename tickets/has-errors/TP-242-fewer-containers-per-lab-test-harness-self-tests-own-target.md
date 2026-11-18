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
- [x] Container starts of the non-matrix lab phase ≤ 170. Evidence: the budget report. (TP-239's report isn't merged: `docker events` start count instead, full `make lab-test` at 61112839: 141, 155 with the harness phase; was 225. Notes.)
- [x] `make lab-harness` passes, and is run by any change under `lab/` non-test files. Evidence: the Makefile rule and a log. (Makefile `lab-harness`, `lab-harness-cached`, `LAB_HARNESS_HASH`; the run at 61112839: `[harness] lab-harness: harness 9508f127… not passed before, running it` … `ok … 388.339s`, then `lab-harness-cached`: `passed before on harness 9508f127…, not run again`.)

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
- **Before, counted** (`docker events --filter event=start` over the run's window, that run's labs only; the budget report, TP-239, isn't merged, so the event count stands in for it): a full `make lab-test` at 3d2f04d8 (rewrite 2da8d775 plus TP-243's node-phase cache, which starts no lab-phase containers of its own): its `lab/` phase, gotest labs and censor-matrix rows left out, started **225** containers, 214 without the harness tests named after the checkout (11). Cross-check on rewrite bdcebaa4: `make lab-gotest PKG=./lab` over every top-level lab-tagged test but TestCensorMatrix, green, 229 starts: 16 harness, 1 the in-node gotest lab, **212** the rest (the 2 of lab/prototypes/reality aren't in ./lab, which accounts for 214 vs 212). Per test it is the topology's node count (TestRouteTableSendsOnlyDirect… 8 nodes; TestServiceUnderSystemd 8 starts of 4 nodes: its device-a starts 5 times, the test restarting the systemd node, and each restart counts).
- **After, counted** the same way: full `make lab-test` at 61112839, green (EXIT 0), wall 3018 s, on a runner busy with four other tickets' lab runs the whole time (so the wall time says little; ev1's 2097 s run at 3d2f04d8 failed early). 259 starts: 41 gotest labs, 63 matrix rows (9 × 7), 14 the harness phase, **141** the rest of the `lab/` phase (was 214 on the same footing: −73, about 4 minutes of Docker starts at 18–20 a minute). Per test it is now the declared node count (TestServiceUnderSystemd 7: its device-a starts 5 times).
- **Start budget**: lab.Start's 10 minutes used to start before the lab slot wait, so a lab queued behind others failed "setup" without starting. Now `labBudget` (lab/lab.go) gives the slot wait its own bound (45 min, under LAB_TIMEOUT's 60) and the start 10 minutes for the part before the slot (leftover removal, binaries) and 10 more from when the slot is held (`startBudget.waitThenStart`).

## Review findings
Review round 1, accepted by the orchestrator: the 31 trimmed tests are sound; the problems are in the harness phase's hash and the start budget.
- [ ] R1.1 (should-fix) The harness hash covers only files holding `func TestHarness`, but the harness tests reach helpers elsewhere (netstate_test.go, main_lab_test.go, harness_test.go) and go.mod/go.sum aren't hashed: harness tests and every helper they reach go into hashed files, go.mod and go.sum are hashed, and a guard test (go/parser, go/ast) fails if a TestHarness test reaches, transitively within package lab, a declaration in a file the hash doesn't cover.
- [ ] R1.2 (should-fix) The stamp is written whenever go test exits 0, even when a harness test skipped (TestHarnessLabStartsOverlapOnDistinctSubnets skips under -parallel < 4): don't stamp a run in which any harness test skipped, and say so.
- [ ] R1.3 (should-fix) Worst case 10 + 10 + 45 + 10 = 75 min, past LAB_TIMEOUT's 60: one bound for everything before the slot, the slot wait bounded by the test's deadline minus the start budget; the oracle checks the real sum; the comment and README say exactly what holds.
- [ ] R1.4 (should-fix) Timeouts don't say which bound expired (slot wait, before-slot preparation, start after the slot): wrap each with its bound; test at least one.
- [ ] R1.5 (nit) `|| exit 1` inside `{ … } | git hash-object` runs in the pipe's subshell, so a failed read still hashes partial input and exits 0: check the files before the pipe and fail on any read error.
- [ ] R1.6 (should-fix) The hash keys only the Go and Docker server versions: add the Docker host's kernel version and the Compose version.
- [ ] R1.7 (nit) harness_test.go: `time.Sleep(5 * time.Millisecond)` in a unit test: use a fixed or injected time.
- [ ] R1.8 (nit) TestOnlyKeepsTheNamedNodesAndTheirNetworks checks names and networks only: check that the kept nodes' specs are unchanged.
- [ ] R1.9 (ticket) Scope says 8 harness tests and 25 trimmed, Notes 9 and 31; box 2's "any change under lab/ non-test files" overstates what the hash covers; drop the "ev1" label from Notes.
- [ ] R1.10 (check) `labctl up` now gets 10 minutes for its build where it had 15: restore it if that wasn't intended; say so in the Log.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-18 backlog → in-progress, owner: agent-tp-242
- 2026-11-18 takeover after the first agent's network drop: WIP at 57caae3d built and checked; its before run had died midway, its labs removed with make lab-down in that checkout
- 2026-11-18 TestIngressOffAdmitsOnlyServers trimmed to five nodes (the WIP had missed it); Notes list every trimmed test
- 2026-11-18 tests: TestStartBudgetCountsFromTheSlot, TestOnlyKeepsTheNamedNodesAndTheirNetworks (unit). Mutations, each seen failing then restored: the start deadline set before the slot wait; the slot wait bounded by the start budget; Only keeping every network; Only ignoring a name the topology lacks
- 2026-11-18 harness hash: a line added to lab/doc.go or lab/censor/doc.go changes it, one added to dns_test.go doesn't, one added to smoke_test.go (it holds TestHarness tests) does
- 2026-11-18 make lint, make test green at 34a0ef6b
- 2026-11-18 before count: full make lab-test at 3d2f04d8 (another branch's run, rewrite 2da8d775 plus TP-243's cache), 225 lab-phase non-matrix starts; cross-check make lab-gotest PKG=./lab at bdcebaa4 without the matrix, green, 212 plus 16 harness
- 2026-11-18 full make lab-test at 61112839: green, wall 3018 s on a loaded runner; the harness phase ran and passed (388 s), then lab-harness-cached skipped it; 141 lab-phase non-matrix starts, 155 with the harness phase
- 2026-11-18 not verified: the wall-time gain on a quiet runner (every run here shared it with other tickets' labs); out of scope: the censor matrix rows start all 7 upstream nodes, some of which a row may not need (TP-236's cells)
- 2026-11-18 in-progress → review
- 2026-11-18 review round 1: fix R1.1–R1.10
