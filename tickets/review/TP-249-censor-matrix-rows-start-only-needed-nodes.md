---
id: TP-249
title: "Censor-matrix rows start only the nodes they need"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-242, TP-236]
refs: []
owner: "agent-tp-249"
branch: "tp-249-matrix-row-nodes"
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). Each matrix row still starts all 7 upstream nodes (63 starts per run); some rows may not need device-b or server-2 (TP-242's out-of-scope note).

## Scope
- Per row, list the nodes its cells drive.
- Use Topology.Only (TP-242) for the rest dropped.
- Keep every verdict.

## Out of scope

## Acceptance
- [x] Container starts of the matrix, before and after, in Notes.
- [x] RESULTS.md verdicts identical (diff), except wireguard × fully-encrypted, a `varies` cell (logged exemptions in Notes).

## Notes
- **Nodes per row.** Before: every row started `lab.Upstream()`, 7 nodes (router, device-a, device-b, server-1, server-2, internet, camouflage). After: every row starts `lab.Upstream().Only(...)` (in `startRow`), 4 nodes (router, device-a, server-1, camouflage; `lab/matrixreset_test.go`). The rows don't differ, because every row runs every case:
  - device-a and server-1 are each row's two ends: thinkpol's udp and reality, the plain-tcp and https controls, kernel WireGuard and OpenVPN's peers, the random-tcp echo server and the relay.
  - router runs censord in every censored cell, and takes `censord -reset` and the conntrack checks of `matrixRow.reset`.
  - camouflage: the `active prober` and `server-hello` cases call `lab.StartCamouflage` in every row and compare that row's server with the site (their modules are configured with its addresses, so the cell can't run without it, even in a row whose server they never probe); relay-tcp and reality splice to it; `startRow` runs it for the clean state. It also builds the udp and reality rows' maps (`newM0Space`'s builder): outside the space, as its admin's machine would be, and not the censor's box; its `/tmp/m0` is removed by the reset like any cell's file.
- **Why each dropped node is in no cell's claim.**
  - device-b: no setup, probe, flow check or module config reaches it. `lab/maps/m0.yaml` and `reality.yaml` name device-b, but only as a map entry: it has no endpoint, so server-1 never sends to it, and before this change its container ran no thinkpol either.
  - server-2: no matrix code names it.
  - internet: its one job was to build the udp and reality rows' maps (`thinkpol dev keygen`, `dev map build`, files under `/tmp/m0`, removed by the reset). The camouflage node does that now (the router at d3cc0390, moved off the censor's box in review). No probe reaches internet, and no cell asserts that traffic doesn't reach it.
  - Nothing else reads the dropped nodes: `matrixRow.reset`, `states` and `check` walk `l.Nodes()`, the nodes the row started. `lab.Lab.Node` panics on a node that wasn't started, so a cell that still needed one would have stopped the run; the after run finished green.
- **Container starts, measured** (`docker events` start events, counted only for the run's own labs by their Compose project prefix; one targeted `make lab-gotest PKG=./lab RUN=TestCensorMatrix` each, on a shared runner with other tickets' labs going):
  - before, rewrite 0679cdf0: 63 matrix starts (9 rows × 7: 9 each of router, device-a, device-b, server-1, server-2, internet, camouflage), plus the gotest node both runs start (64 in all); `ok` 1203.7 s, 1260 s wall.
  - after, d3cc0390: 36 matrix starts (9 rows × 4: 9 each of router, device-a, server-1, camouflage), plus the gotest node (37 in all); `ok` 1254.2 s, 1328 s wall.
  - 27 fewer starts per matrix: about 1.5 minutes of Docker's start rate at the runner's ~18–20 a minute. The matrix wall time didn't drop: the two wall times are within the noise of the shared runner (other tickets' labs ran throughout both). The matrix's wall time is its longest row's (the held reality and udp rows, about 13–16 minutes here), so fewer starts move it less than they move the Docker load the other tests see. The rows' summed time fell from 5100 s to 4378 s, but rows include their slot waits, so that number is load as much as starts.
- **Verdicts.** Comparing the two runs' RESULTS.md on the transport, censor and result columns (the detail column carries per-run addresses and timings): 90 cells each, and 89 identical. The one difference is the known-chance cell wireguard (reference) × fully-encrypted, partial before and pass after. Its logged exemptions show why. Before, only the IPv4 initiation was exempt (`exempt: 3.28 set bits per byte, 148 bytes`), and IPv6 was dropped, so it scored partial. After, both families' initiations were exempt (3.28 and 3.26 set bits per byte), so it passed. That cell `varies` by design (the matrix expects any result from it) (an initiation passes Wu et al.'s first exemption about one time in four). Re-run once on d3cc0390 (`RUN='TestCensorMatrix/^wireguard/^(off|fully-encrypted)$'`): off pass, fully-encrypted fail, with neither initiation exempt and the test passing. So across three runs that cell scored partial, pass and fail, as `varies` allows. udp × fully-encrypted, whose expected result is `fail` (not a `varies` cell), failed in both runs.
- **TP-239** splits the held cells into a long stream but still opens every row's lab, held or not, through `startRow`. So once it lands, its held-row labs are trimmed too and need no other change.

## Review findings
- [x] R1.1 the udp and reality rows build the space's map and keys on the camouflage node (outside the space, not the censor), not the router.
- [x] R1.2 the row's node list is local to `startRow` (no package-level slice); TestCensorMatrix's doc and lab/README.md name the nodes.
- [x] R1.3 Acceptance and Notes: verdicts identical except the `varies` wireguard × fully-encrypted cell; udp × fully-encrypted is an expected `fail`; the matrix wall time didn't drop.

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-249
- 2026-11-19 censor-matrix rows start `lab.Upstream().Only(router, device-a, server-1, camouflage)` (`matrixRowNodes`, lab/matrixreset_test.go); the udp and reality rows build their maps on the router, not internet; lab/README.md's matrix paragraph and TestCensorMatrix's doc updated
- 2026-11-19 targeted matrix runs: before (rewrite 0679cdf0) 63 matrix container starts, ok 1203.7 s; after (d3cc0390) 36, ok 1254.2 s; verdicts identical but for wireguard × fully-encrypted (partial / pass, logged exemptions in Notes), re-run once on d3cc0390: fail, as varies allows
- 2026-11-19 no new test, so no mutation: a cell that needs a dropped node panics in lab.Lab.Node, and the after run finished green; make test green on d3cc0390; no full make lab-test (the brief's 2026-11-18 rule: targeted runs only)
- 2026-11-19 make lint green on 56985e28 (code as d3cc0390)
- 2026-11-19 in-progress → review
