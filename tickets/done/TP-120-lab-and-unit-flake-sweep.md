---
id: TP-120
title: "Flake sweep: tests that fail under load"
milestone: M2
area: tests
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-120"
branch: "tp-120-flake-sweep"
---

## Goal
A red `make test` or `make lab-test` means a real defect. Every test seen failing once under load and passing on a rerun is made deterministic, or its failure is shown to be a product bug and fixed or filed.

## Scope
Seen on 2026-10-21 with several agents running tests and labs at once (each passed alone and on the rerun):
- `internal/dataplane/blobs` `TestATricklingPeerIsAbandoned` (unit): `Abandoned:7` instead of 1. Under CPU load the good peer also misses the ~0.3 s rate window (`MinRate 1<<20`, `DialTimeout 300ms`) and is abandoned. Assert what the test means (the trickling peer abandoned, the good one fetched), or give the good peer headroom that load can't eat.
- lab `TestTwoSpacesShareAListener`: "no reply for a dialer".
- lab `TestSwitchesPathWhenTheRelayCloses/datagram` (`internal/dataplane/path`).
- earlier ones to re-check: the TP-113 Log's `transporttest` ShapingRefused (keep the line next time), and any other test the recall notes tagged `kind:flake` list.
For each: reproduce under load (e.g. `-count` with `-p` raised, `stress`-style parallel runs, or a CPU hog alongside), find the cause, fix the test (or the code if the code is wrong), and show it holds (N runs under the same load).

## Acceptance
- [x] each listed test: cause in the Log, fix, and a loaded repeat run that passed (count and load stated)
- [x] a product bug found this way is fixed here if small, else filed
- [x] `make lint`, `make test`, `make lab-test` pass

## Log
- 2026-10-21 created in backlog (flakes seen during TP-112, TP-102 and TP-116 runs)
- 2026-10-21 backlog → in-progress — owner: agent-tp-120, branch: tp-120-flake-sweep
- 2026-10-21 blobs TestATricklingPeerIsAbandoned: cause: the device's window is 0.3 s per transfer, and a held-up good peer misses it too and is abandoned until a later round fetches from it (Abandoned:7, Fetched:1; reproduced exactly by delaying the good peer's first 3 dials by 350 ms). The 5 s elapsed bound couldn't tell abandoning from waiting out the 1 s trickle. Fix (9f08b73): the trickling peer (now 4 s) reports when the device hangs up before its last byte; the test asserts that hang-up, Abandoned > 0, Fetched == 1 and Rejected == 0. Mutation: transferTimeout returning an hour fails it ("the device never hung up on the trickling peer"). Loaded: 8 parallel -race processes x 20 runs x -cpu 1,4 (320 runs) beside a 16-process CPU hog for 100 s, and lab-gotest COUNT=40 beside three other labs: all passed.
- 2026-10-21 lab TestTwoSpacesShareAListener ("no reply for dialer"): product bug in internal/agent/supervisor shared.go: forward handed the datagram to the worker and only then remembered its source as a reply destination; the worker (another process) can answer first, and reply refused the answer (RepliesNotAllowed). Fixed (28d9fa3): remember before the hand-off; DESIGN.md's rule (the source of an authenticated, fresh, non-replayed datagram) still holds when the hand-off then fails. New TestAnAnswerMayBeatTheHandOff answers from inside TrySendDatagram; mutation: remember back after the hand-off fails it (Replies:0 RepliesNotAllowed:1). Not reproduced in the lab on the old code (40/40 under a concurrent package run). Loaded: lab-gotest COUNT=20 with another lab and host make lint/test running, COUNT=15 for the unit tests beside three other labs: all passed.
- 2026-10-21 transporttest ShapingRefused behind the supervisor (TP-075, TP-113 Log): the same forward bug. At 80469c6 line 1209 is fixedClient.expect("accepted"), a server-writes-first step whose reply went through reply(). A 2 ms pause injected after the hand-off makes the old order fail ShapingRefused with "no packet within 5s"; with the fix and the same pause the whole conformance suite passes. Loaded: TestConformanceBehindTheSupervisor COUNT=15 beside three other labs: passed.
- 2026-10-21 path TestSwitchesPathWhenTheRelayCloses/datagram ("send before: no path to the peer"): cause: wall-clock DeadAfter is 150 ms, so a load stall leaves every link of A unproven at once; the tick closes them, and until a redial is answered Send returns ErrNoPath (a.send fatals) or takes the first linked hop. Reproduced: a 300 ms silence of A's links before "before" fails the old test 3 of 40 with the recorded error; the fixed test passes 40/40. Fix (8b5a023): resend until the packet arrives (keepSending) and wait for the hop to settle (settlesOn); the same applied to TestSwitchesPathWhenTheFirstHopGoesSilent, which shared the pattern (its 10 x DeadAfter switching bound stays: it is the NFR it checks). Mutation: Failover never leaving the current hop fails it ("after" never arrived). Loaded: 8 parallel -race processes x 25 runs x -cpu 1,2 beside a 16-process hog for 120 s, and lab-gotest COUNT=40 beside three other labs: all passed.
- 2026-10-21 lab TestTheOverlayComesBackAfterALinkBounce (MTU 1400): already fixed on rewrite by ede456e (TP-102: waits for the address and the MTU; the re-apply cooldown is 1 s against a 10 s wait). Loaded: lab-gotest COUNT=10 beside three other labs: passed.
- 2026-10-21 lab TestForgedICMPErrorsAreRefused/bound=false: the recorded failure (TP-100 round 3) predates b876e8c, which fixed its cause (the root's conntrack flow expiring under load). Loaded: lab-gotest COUNT=20 with another lab and host make lint/test running: passed.
- 2026-10-21 blobs TestAPeerDroppedFromThePlanIsServedNoMore ("connection refused"): fixed in TP-113 (waitServing). Loaded: lab-gotest COUNT=40 beside three other labs: passed.
- 2026-10-21 out of scope, for the orchestrator: supervisor TestDeafWorkerHoldsNothingUp fails without closing its supervisor, so every later supervisor test in the binary fails with "a configurator of this owner is already alive in the namespace" (seen after an unrelated failure); its supervisor wants a t.Cleanup Close. Also: two lab-gotest runs from one checkout rebuild the same lab/bin/tests binary under each other ("fork/exec /proc/self/exe: no such file").
- 2026-10-21 not verified: none of the flakes reproduced on the old code under bounded load (each was shown by injecting its stall or delay instead); merged origin/rewrite at ce88ea7.
- 2026-10-21 make lint, make test and make lab-test (LAB_P=4, no other lab at the start; both phases ok, 35 packages in nodes) pass at ce88ea7
- 2026-10-21 in-progress → review
- 2026-10-21 round 1: correctness says merge; design asked for small fixes, applied by the orchestrator: TestDeafWorkerHoldsNothingUp and TestCloseRemovesEverything close their supervisor on failure (one failure no longer fails every later test); TestTwoSpacesShareAListener prints the shared counters when no reply comes; forward's comment says a failed hand-off still counts and why; TestANewMapAbandonsAStalledTransfer waits for the cut instead of a 4 s bound; settlesOn → reachesHop (from, and its leftover packets documented); a refused datagram from a new address leaves no reply address (mutation: remember above Allow fails it). The lab/bin collision of two lab-gotest runs from one checkout is filed separately
- 2026-10-22 merged to rewrite (correctness, design and Grok: merge); Grok's nit applied: TestSwitchesPathWhenTheRelayCloses now requires R1 before the close
