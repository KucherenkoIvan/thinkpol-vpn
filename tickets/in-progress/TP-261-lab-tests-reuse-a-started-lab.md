---
id: TP-261
title: "Lab tests reuse a started lab instead of starting their own"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: L
depends_on: [TP-260]
refs: []
owner: "agent-tp-261"
branch: "tp-261-lab-reuse"
---

## Goal
Most lab tests start a fresh lab (4–7 containers) that lives seconds to a minute, so a run spends most of its time starting labs (57 starts × ~1 min in a warm run). TP-240 showed a reset+check between users of one lab is reliable (the matrix rows). The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- A small pool of started labs per topology that tests take, use, and return after a verified reset (TP-240's snapshot/reset/check).
- Tests that must have a fresh lab are marked and keep getting one.
- Start with the most common topologies.

## Acceptance
- [ ] Lab starts per full lab, before and after, in Notes (target: at least halved).
- [ ] Every reused lab passes the reset check before the next test gets it; a failed check retires that lab (test).
- [ ] Full-lab wall time before and after, in Notes.

## Notes

### Plan (2026-11-19)

**What the `lab/` tests change on their nodes**, by topology (S = `lab.Standard()`, U = `lab.Upstream()`; R router, A/B device-a/-b, S1/S2 server-1/-2, I internet, C camouflage):

| Topology | Tests | What they leave on the nodes | Verdict |
|---|---|---|---|
| S{R,A,S1} | TestCensorForwardsWhatNoModuleDecides, TestCensorFragmentedUDPBlocked, TestTCPResetReachesClient, TestTCPThroughCensorDrop, TestTCPResetReachesBothEnds, TestCensorReplaysClientHello, TestFullyEncryptedRandomNotHTTPS, TestDiagShowsWhatTheHostHolds, TestCaptureFlagsRawWireGuard, TestHealthWithNoLinkUp, TestShapingCapture, TestTheNodeFileSetsUp (its hand-written topology is this one) | processes (`thinkpol up`, censord, tcpdump, nc, socat, dbus-daemon and systemd-resolved in diag), links (TUN, `wg0`), addresses, routes and rules in thinkpol's tables, nft tables (`thinkpol-*`, `censor`, the tests' own `tp140`, `sink`), queue bindings, files under `/tmp`, `/run`, `/var/lib/thinkpol`, `/etc` (diag's `groupadd`, resolv.conf), conntrack (censor's ct match, docker's DNS nat table in every node), forwarding sysctls | reusable after reset |
| S{R,A,B,S1} | TestLocalAPI, TestUpRunsTheM0Space, TestM0 (two subtests, own slot each), TestTheCLIExitsBySysexits (S{R,B,S1}: device-a idle) | as above, plus `/run/foreign-api`, `/etc/resolv.conf` | reusable after reset |
| S{R,A,B,S1,I} | TestASecondAgentChangesNothing, TestDNSFollowsTheRules, TestDisconnectLeavesNothingBehind | as above; DNS tests rewrite `/etc/resolv.conf` (a bind mount: restored in place) | reusable after reset |
| S{R,A,S1,I} | TestDNSFollowsTheRulesOnAServerExit | as the DNS tests | reusable; joins S{R,A,B,S1,I} (device-b idle there): a pool of its own would be one lab for one test |
| S{R,A,S1,S2,I} | TestBlobDistribution, TestEgressThroughAnExit, TestHealthWithAnExitThatNeverHandshakes | as above, plus addresses on `lo`/eth, host routes, masquerade (conntrack NAT entries) | reusable after reset, in the whole-`Standard()` pool |
| U{R,A,S1,C} | TestProberTellsEchoFromNginx, TestServerHelloAgainstTheSite, the censor matrix's row labs (TP-240: already reset per cell) | nginx (camouflage), censord and its table/conntrack, transports' processes/links/files | reusable after reset; a matrix row takes a pooled lab, keeps its own per-cell reset on top |
| U{R,S1,C} | TestCensorSeesUpstream | nc listeners, censord | reusable; joins U{R,A,S1,C} (device-a idle there) |
| S{R,A,B,S1,S2} | TestIngressOffAdmitsOnlyServers | as above | reusable; the only test of its topology, so it and S{R,A,S1,S2,I} share one pool of the whole `lab.Standard()` (internet, device-b idle where unused) |
| S{R,A,I} | TestSmoke | — | **fresh**: checks the lab's own start (sealing, hermetic) |
| custom with systemd nodes | TestKillSwitchUnderSystemd (4 parts), TestRollbackPutsTheHostBack…, TestServiceUnderSystemd, TestServiceUninstallAfterAServerCrash | systemd units and their enablement, `/etc/systemd`, `/usr/local/bin/thinkpol`, the journal; TestServiceUnderSystemd restarts the container (`Node.Restart`, docker-level) | **fresh**: systemd state and container restarts are outside what the reset can verify (a later step may pool the kill-switch/rollback topology, 5 labs, if the halving needs it) |
| custom (S + `abroad`/`router-2`, xray) | TestNoIPv6LeavesAroundTheTunnel, TestRouteTableSendsOnlyDirect…, TestRealityStockXray | as above | singletons: stay `lab.Start` |
| harness | TestHarness* | the lab itself | **fresh**: they test lab start, teardown, isolation |

No `lab/` test outside the systemd ones disconnects a network, restarts, pauses or kills a container.

**Design.**
- `lab.NewPool(topo, size)`: a process-wide pool of at most `size` started labs of one topology; `pool.Acquire(t)` gives the test an idle lab, starts one (its own lab slot, held while the lab lives) while the pool has fewer than `size`, or waits (first come, first served) for one to come back. At the test's end (`t.Cleanup`, registered first so it runs after the test's own clean-ups) the lab is reset and checked; it goes back to the pool only when the check passes. A failed check retires it (torn down, the reason logged), and a failed test's lab is retired too (or kept with `THINKPOL_LAB_KEEP`), so the next test gets a fresh one. An idle lab is torn down after a short grace, so idle labs don't sit on slots other runs wait for; `lab.Main` tears down whatever the pools still hold. Tests that need a fresh lab keep calling `lab.Start`/`lab.StartOwnSlot`: that is the opt-out.
- The reset is TP-240's (`matrixRow.reset`) moved into package `lab` (`Lab.Snapshot`, `Lab.Reset`) and widened: processes, links (and their flags and MTU), addresses, routes in every table, policy rules, the nftables ruleset by table (tables a test added are deleted; a changed harness table fails the check), queue bindings, mounts, xfrm states and policies, qdiscs, net sysctls (restored to their snapshot values), the whole writable filesystem but `/usr` (new paths removed; `/etc` by content, restored in place from a copy taken with the snapshot; other files' size and mtime checked, `/var/log` by name only), and conntrack on every node (flushed until it stays empty). Anything the reset can't put back fails the check (prefer failing over guessing). The matrix rows keep their per-cell reset through the same code.
- Pools are declared in one file (`lab/pools_test.go`), with their sizes, so the reuse is visible in one place.
- Proof: unit tests of the snapshot diff/undo; a lab test that leaves state behind on purpose and sees the lab retired (mutation: skip the check, and a later user sees the leftover); the timeline's lab starts and the full lab's wall time before and after.

### Measurements

- **Before** (rewrite 35b02ca7, this branch's board commit cc9c380c, full `make lab-test` with `THINKPOL_LAB_TIMELINE`, cold node phase and harness, another ticket's full lab running at the same time): tests passed, over budget (default stream 47m52s, long stream 4m13s), wall 2872 s. Lab starts (`docker compose up` lines in the timeline): 111 in all, of which 57 by the lab tests of the two streams (`lab/` and `lab/prototypes/reality`: TestKillSwitchUnderSystemd 4, the censor matrix's rows 17, every other test 1), 12 by the harness tests, 42 by the node phase.
- Targeted run of the 25 migrated tests (`make lab-gotest PKG=./lab RUN=…`, 7d13d6d4, under two other tickets' full labs): all passed, 798 s; 20 labs started for 28 tests, none retired; most labs went down idle after one test (a fixed 15 s idle grace), hence the grace now follows the lab's own start time.

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-261
- 2026-11-19 plan in Notes; built `lab.Pool` (pool.go: Acquire, size, first-come-first-served waiters, idle grace = the lab's own start time within 15 s to 3 min, retire on a failed test or reset, Main tears down) and moved TP-240's snapshot/reset/check into package lab (snapshot.go: Snapshot, Reset, Check), widened to links' flags/MTU, the nft ruleset by line, mounts, xfrm, qdiscs, net sysctls, the filesystem but /usr (/etc by content/mode/owner/symlink, restored from a copy), conntrack on every node; the matrix rows take their lab from the censor pool and reset through it; 26 tests moved to five pools (pools_test.go)
- 2026-11-19 mutations (each restored after): undoSettings returns nil → TestNodeState fails; set instead of multiset diff → TestNodeState fails; handOn LIFO → TestPoolTake fails; Lab.Reset skips its Check → TestHarnessPoolResetsOrRetires's third user gets the same lab with /etc/localtime re-pointed; giveBack skips Reset → its second user sees all 14 leftovers (link, rule, table 100, nft table, netns, files, resolv.conf, /etc file, mode, sysctl, MTU, processes, connection, conntrack)
