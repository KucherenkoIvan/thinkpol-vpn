---
id: TP-279
title: "A server reports its map applied while its first apply is still opening listeners"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-279
branch: tp-279-applied-means-serving
---

## Goal
A server's status, and its "map applied" log line, say the map is applied only once every listener of it serves, so a caller waiting on them (the lab's `mapApplied`, an operator) knows the server is reachable.

## Scope
- A server's status reads the new map version, not retrying, while its first apply still opens the listeners (and, on reality, checks the target), and the "map applied" line (`internal/agent/node.go:1007`) comes before the workers know the listeners (TP-278).
- So the lab's `mapApplied` helper (`lab/nodestatus_test.go:228`) passes early, and the censor matrix starts device-a before the server listens. This hid TP-230's bug (a listener that never opened, retried every 5 s) from the matrix's reality setup.
- Either status and the log line come only after every listener serves, or status gets a separate "serving" field; the lab waits on it.

## Out of scope
- The supervisor serving a listener before its workers know it: TP-278 (this ticket's "serves" means after that fix, or must include it).

## Acceptance
- [x] A server's status and its "map applied" line come only after every listener serves (or a separate "serving" field says so), with a test that holds a listener's open and sees neither before it ends. (`TestServerSaysAppliedOnceItsListenersServe`, `internal/agent/server_test.go`: SetListeners held on the first map and on map 2; mutations M1-M4 in the Log.)
- [x] The lab waits on it: `mapApplied` (or its replacement) passes only once the server serves, and the matrix's setups use it. (`mapApplied` already required connection serving and every worker ready; both now mean served and routed to. `setupUDP` and `setupReality` wait on it; the reality row's idle watch dropped its wait for the log line. `TestStatusChecksFailWithoutTheirFact` gained the connecting case; `TestWorkerIsReadyOnceRoutedTo` in the supervisor's lab tests.)

## Notes
- Found in TP-230 (2026-11-22).
- Design (2026-11-22): the smaller honest change is the existing Connection field, not a new one: a server reads `connecting` (health: starting) until its first serve of the map has ended, then `serving` (`report.serving`, set by the run loop after the first apply returns: every listener serving, since SetListeners returns once they do (TP-278), or retried, Retrying set). No proto, local API or CLI change, and `mapApplied` already required `serving`. A later map's version already showed only after its apply returned, and the "map applied" line is logged after SetListeners returns, so both follow TP-278 with no change of their own. A prepared node that isn't running reads `connecting` too (it serves nothing).
- A worker's `Ready` (WorkerInfo, the local API's worker ready) is now set when the shared listeners attach it, not at its Ready message: between the two, a connection routed to its space would be refused for lack of a worker, and `mapApplied` waits for every worker ready.
- Built on TP-278 (branch `tp-279-applied-means-serving` starts from TP-278's): merge TP-278 first. Not in `depends_on`, since the board allows backlog → in-progress only once every dependency is done.

## Review findings
Round 1 (2026-11-22, on dda4e0f0): correctness (fix first), style (fix first), design (fix first), second opinion (fix first).
- [ ] R1.1 Blocker: serving and "map applied" follow SetListeners returning, which TP-278's round 1 R1.1 shows returns at once while the space's worker is starting (not attached): both come before a connection can be handed to a worker. Fixed with TP-278's R1.1; add a test that the status and the log line never come before the first stream would reach an attached worker.
- [ ] R1.2 `serving` means "the first apply returned": a failed apply (Retrying, every listener down) and the StopTimeout fallback read serving. Decide and document what a server's Connection reads for: first apply in progress; every listener failed (Retrying); some failed; the StopTimeout fallback used; a later failed replace. Rename the field if it keeps another meaning.
- [ ] R1.3 A stopped server reads Connecting, unlike a stopped device (Disconnected): make it read like one, unless the package doc says why not.
- [ ] R1.4 Names and tests: `session.routed` → `markReady`; got/want in `TestServerSaysAppliedOnceItsListenersServe`'s messages; `TestWorkerIsReadyOnceRoutedTo`'s polling loop bounded.

## Log
- 2026-11-22 created in backlog (from TP-230's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-279
- 2026-11-22 done: a server's Status reads connecting until its first serve of the map has ended, then serving; a worker reads Ready once the listeners route to it; mapApplied's doc, its check test and the reality row's idle watch follow. Tests: TestServerSaysAppliedOnceItsListenersServe (agent), TestWorkerIsReadyOnceRoutedTo (supervisor, lab), TestStatusChecksFailWithoutTheirFact's connecting case (lab); TestAServerRefusesConnect and the resolver tests' serverSpaces updated to the new meaning
- 2026-11-22 mutations (each fails its test, then restored): M1 a server always serving → TestServerSaysApplied… fails (connection serving while held); M2 the run loop never sets serving → fails (never serving); M3 the "map applied" line logged before SetListeners → fails; M4 a new map's version reported at take, before its serve → fails; mapApplied without the connection check → TestStatusChecksFailWithoutTheirFact fails (lack 4, the connecting case); Ready at the Ready message (the code before the fix) → TestWorkerIsReadyOnceRoutedTo fails in the lab on 6209daf9 (ready 20 ms after start, before the acknowledgement; EXIT=2)
- 2026-11-22 runs on 16796283 (rewrite 883b150c merged): make lint 0 issues and make test pass (exit 0); make lab-gotest PKG='./internal/agent/supervisor/... ./internal/dataplane/transport/reality/... ./internal/dataplane/transport/udp/...' ok, none cached (supervisor 56.3 s, udp 1m7 s, reality 1m24 s); make lab-gotest PKG=./lab RUN='^TestCensorMatrix$/^(udp|reality)|^TestStatusChecksFailWithoutTheirFact$' ok in 224.5 s, all five labs PASS, reality × active prober NOT JUDGED as on TP-278's runs. Lab speed: the five labs up in 51-54 s, cells 1m26s-2m21s, against 47-51 s and 1m27s-2m13s on TP-278's run of the same rows: no fixed wait added
- 2026-11-22 not verified: the local API and CLI showing a starting server as connecting on a real host (covered by Status and convert's existing mapping); no full make lab-test (brief: targeted runs only)
- 2026-11-22 in-progress → review
- 2026-11-22 rewrite fa427ca0 merged (75bcbdb8), runs again on it: make lint 0 issues, make test pass; lab-gotest supervisor/reality/udp ok, none cached (55.7 s, 1m24.4 s, 1m12.7 s); TestStatusChecksFailWithoutTheirFact and the matrix udp and reality rows ok in 216.6 s, five labs PASS, reality × active prober NOT JUDGED as before
- 2026-11-22 review → has-errors: round 1 findings R1.1-R1.4 (fix first)
