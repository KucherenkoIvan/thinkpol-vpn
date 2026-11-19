---
id: TP-247
title: "The censor matrix's slow rows split across labs so the default stream fits its budget"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-239, TP-241, TP-236]
refs: []
owner: "agent-tp-247"
branch: "tp-247-split-matrix-rows"
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). Since TP-240 each transport row runs its cells one after another in one lab; the reality row's cells take ~8m19s even without the rhythm hold (TP-239's budget report), which alone rules out 15 minutes.

## Scope
- Measure each row's serial time from the budget report.
- Split the slowest rows into 2–3 labs (or run independent cells of a row in parallel where they don't share state), trading a few container starts for wall time.
- Keep every reset check (TP-240) and every verdict identical.

## Out of scope

## Acceptance
- [ ] The matrix's longest default-stream lab ≤ 5 minutes. Evidence: the budget report. Moved to TP-254 (lab concurrency follows the slot cap). In the targeted matrix run on 27ba73b3 the longest lab took 193 s (it was 410 s before the split), but not in the full lab on 27ba73b3: there the unsplit https and wireguard rows took 14m28s and 12m6s, almost all of it waiting for a lab slot (their cells take under 2 minutes), and the split rows' labs took up to 6m35s. Round 1's targeted run on ea1ef19e, on a loaded machine, waited up to 13m41s for a lab to start (Notes).
- [x] RESULTS.md verdicts identical to the per-row run (diff), except wireguard × fully-encrypted (varies, logged exemption) and reality × active prober (timing flip, TP-255). Same cells and results in every run apart from those two (Notes). wireguard × fully-encrypted is declared `varies` and its exemption is logged. reality × active prober passed in 3 of 10 earlier runs on rewrite branches.
- [x] Container starts added, in Notes.

## Notes
- Layout (`transport.labs`, `rowLabs` in lab/results_test.go): a row's cells of a stream are dealt in turn across `labs` labs (its held cells in the first since round 1), run as parallel subtests `<row>`, `<row> lab 2`, `<row> lab 3`; each lab runs the off cell first as its own gate, and only the first lab records it, so every cell is recorded once and the stream shares and RESULTS.md assembly are unchanged. reality: 3 labs; udp, openvpn-udp, openvpn-tcp, random-tcp: 2; plain-tcp, https, wireguard, relay-tcp: 1. Quiet-machine cell sums per lab come to 50–103 s (wireguard's unsplit 103 s is the most). The long stream is unchanged: one lab per held row.
- Container starts: the default stream's matrix went from 9 labs (36 containers) to 15 labs (60 containers), 24 more per run; the long stream stays at 2 labs (8).
- Each matrix lab logs `lab: up in …, cells …, down in …` (startRow). Lab start (slot wait, 4 containers, camouflage) measured 16 s to 2m53s per lab under load, often more than the lab's cells. Under a loaded full lab the start dominates, so no split of cells keeps a lab under 5 minutes there.
- Targeted default-stream matrix runs (`THINKPOL_LAB_STREAM=default make lab-gotest PKG=./lab RUN='^TestCensorMatrix$'`):

  | run | commit | labs (containers) | longest lab | matrix wall |
  |---|---|---|---|---|
  | before | 6c24d695 (rewrite) | 9 (36) | 410 s (reality) | 702 s |
  | after, under load | 33a40d1e | 15 (60) | 334 s (openvpn-tcp lab 2: up 2m53s) | 656 s |
  | after, final | 27ba73b3 | 15 (60) | 193 s (relay-tcp) | 412 s |

  The final run had less load than the before run; the final commit also has TP-251 merged.
- Verdicts: 86 of 88 default-stream cells are the same in every run. Two cells vary by chance. wireguard (reference) × fully-encrypted is a declared `varies` cell: it was partial in one run and pass in another, and each time the log names the exemption that let a family through (`exempt: 3.36` and `3.35 set bits per byte`). reality × active prober came out not judged before and pass after: "a baseline shorter than the probing, too short to call the tell unattributable". That cell flips by timing alone: it passed in 3 of 10 earlier runs on rewrite branches (TP-236, TP-241), so it doesn't come from the layout.
- Reset race found and fixed: with the split, reality's ip-blocklist cell runs right after the off cell. Its reset then failed in 3 of 8 reality-lab-2 runs (also once in TP-240's own run) with "3 conntrack entries outlived the reset". Listing the entries showed server-1 → camouflage:443 in the retransmission state: REALITY's handshakes with its target, cut mid-stream by ip-blocklist, kept retransmitting from server-1's orphaned sockets after the router's flush. `matrixRow.reset` now aborts every TCP connection a node still has after the kill (`ss -K -t state connected`; the clean state has listeners only; an RST makes no conntrack entry of its own), and `check` lists leftover entries. After the fix: 5 of 5 reality-lab-2 runs passed, then the full targeted matrix.
- Full `make lab-test` on 27ba73b3: 2053 s wall. All tests passed and RESULTS.md was assembled from both streams. The default stream took 34m12s, over its 15m budget, with the node phase uncached (40 packages ran); the long stream took 4m6s. Slowest tests: TestCensorMatrix/https_(control) 14m28s, TestCensorMatrix/wireguard_(reference) 12m6s, TestKillSwitchUnderSystemd/down 7m30s, lab/censor 7m0s, TestCensorMatrix/openvpn-udp_(reference)_lab_2 6m35s, TestM0/underlay=ipv4 6m31s, internal/shaping 6m26s, TestCensorMatrix/openvpn-tcp_(reference) 6m3s. Its RESULTS.md against the before run's cells differs only in the two chance cells above (wireguard × fully-encrypted partial, reality × active prober pass).
- An earlier full lab on e60da648 (before the reset fix), run beside another full lab: 2536 s, default stream 42m16s, also with the node phase uncached. It failed only on the reset race above (reality lab 2, ip-blocklist), so RESULTS.md wasn't assembled.
- Round 1 (2026-11-19). Held cells now stay in the row's first lab: before, with no stream (`make lab-test-rhythm-real`), the rhythm cells went to "reality lab 3" and "udp lab 2" and the target ran only the off cells. Labs start in order of expected time (`matrixLabs`; `cellTime` per row from the final targeted run's cells: reality 20 s, udp 16 s, openvpn-udp 15 s, openvpn-tcp 14 s, random-tcp 12 s, https, wireguard and relay-tcp 11 s, plain-tcp 8 s). In the default stream the unsplit https, wireguard and relay-tcp labs (11 cells each, ~2 minutes) now start first; before, they started after reality's and udp's split labs.
- Round 1 targeted default-stream matrix on ea1ef19e, on a loaded machine (another ticket's full lab and other labs running): 88 of 88 cells, all as expected, verdicts the same as on 27ba73b3 apart from wireguard × fully-encrypted (partial this time, `exempt: 3.39 set bits per byte` logged). reality × active prober passed, as on 27ba73b3. Matrix wall 1654 s, longest lab 965 s (wireguard, 13m41s waiting to start, cells 1m43s). Lab starts took 37 s to 13m41s, so the budget numbers say nothing about the split under this load. The labs started in `matrixLabs`' order: https, wireguard, relay-tcp, openvpn-udp, openvpn-tcp, reality, reality lab 2, udp, ...
- The reset's abort, as logged in that run: 316 TIME-WAIT, 6 ESTAB, 3 CLOSING and several FIN-WAIT-1/2 sockets aborted across the cells. This kernel's `ss -K` aborts TIME-WAIT sockets too. No connection outlived an abort. Over 10 runs of reality lab 2 (off, ip-blocklist, openvpn-fingerprint, server-hello), the reset after ip-blocklist aborted server-1's FIN-WAIT-1 sockets to the camouflage site's :443 each time, the orphans that caused the conntrack leftover; all 10 passed.
- `make lab-test-rhythm-real` on ea1ef19e ran just the reality and udp labs, each with its off cell and its wireguard-rhythm cell at real time (held 7m30s, about 465 s per cell). Both failed as expected (udp on the rekey exchange, reality on the burst, a known tell accepted), and the run passed in 577 s.
- Out of scope, but the bigger lever for the 15-minute budget: neither `make lab-test` nor `lab-gotest` passes `-test.parallel`, so `./lab` runs only as many parallel tests as the machine has CPUs (GOMAXPROCS), fewer than the 12-lab slot cap: in a targeted matrix run, three of the nine rows waited for the others to finish before they started. Splitting rows adds labs behind that limit.

## Review findings
- [x] R1.1 (blocker) `make lab-test-rhythm-real` filters `TestCensorMatrix/^(udp|reality)$/^(off|wireguard-rhythm)$`, but the rhythm cells are dealt in turn into "reality lab 3" and "udp lab 2", so the target runs only the off cells and goes green having tested nothing. Deal the held (rhythm) cells to each row's lab 0 (assert it in TestRowLabs) and make the filter match the lab subtest names robustly; show the target runs both rhythm cells (real timers) once.
- [x] R1.2 (should-fix) lab/matrixreset_test.go: `ss -K` exits 0 and kills nothing on a kernel without INET_DIAG_DESTROY (and leaves TIME_WAIT). After it, check that no TCP connection survives on each node (connected and closing states) and fail the reset, listing them, if any does; log per node what `ss -K` killed. Run reality's ip-blocklist lab 10 times.
- [x] R1.3 (should-fix) TestRowLabs tests rowLabs, not its call site: `ml.recordsOff()` → `true` and ranging over `censored` instead of `ml.cells` both pass it. Cover the wiring (move the record decision into what the test calls), assert cells keep censorCases order within a lab, and make writeResults (no-stream path) refuse duplicate rows.
- [x] R1.4 (should-fix) lab/results_test.go: the "longest first" start order no longer holds (unsplit wireguard, the most cell time, starts after split labs; the -parallel limit makes order matter). Order labs by expected cell time and fix the comment.
- [x] R1.5 (nit) the conntrack listing is duplicated in lab/matrixreset_test.go: one helper.
- Fixed in ea1ef19e. R1.1: `rowLabs` (lab/results_test.go) puts a row's held cells in its first lab, the subtest named after the row, alone there when the row has other labs, so the target's `^(udp|reality)$` selects them; TestRowLabs asserts it, and TestRhythmRealTarget reads the target's `-run` filter from the Makefile and matches it as go test does against `matrixLabs`: every held cell and its lab's off cell, no other cell or lab. R1.2: `matrixRow.abortTCP` (lab/matrixreset_test.go) logs per node what `ss -K` aborted, then lists the TCP connections still there (`state connected`, the closing states included, TIME-WAIT left out: it sends nothing unless a FIN comes again, and the peer end that could send one was aborted) and fails the reset if there are any (`tcpAborted`, TestTCPAborted). R1.3: a lab's plan is its `cells` with the record decision in each (`labCell.record`, the off cell first); the matrix loop runs that plan, and TestRowLabs counts the recorded cells from it and checks the off cell comes first and the cells keep censorCases' order; `writeResults` refuses a cell recorded twice (`recordedTwice`, TestRecordedTwice). R1.4: `matrixLabs` orders every row's labs by expected time (the row's measured `cellTime` per cell plus held cells' holds), longest first; TestRowLabs checks the order. R1.5: `conntrackCount`, `conntrackEntries`, `conntrackLeft`.

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-247
- 2026-11-19 baseline: targeted default-stream matrix on 6c24d695, 9 row labs, longest 410 s (reality), matrix 702 s
- 2026-11-19 rows split across labs (`transport.labs`, `rowLabs`, `matrixLab.recordsOff`), per-lab start/cells/teardown log in startRow; TestRowLabs. Mutations, each killed by TestRowLabs: every cell dealt to the first lab; no clamp to the row's cell count; every lab records the off cell; the long stream starts labs for rows without held cells; no row split; every lab named after the row; a cell dealt to two labs
- 2026-11-19 targeted matrix on 33a40d1e (split, loaded machine): 15 labs, longest 334 s, matrix 656 s; verdicts as before apart from the two chance cells (Notes)
- 2026-11-19 full lab on e60da648 failed only on reality lab 2's reset after ip-blocklist (3 conntrack entries). Reproduced in 3 of 8 targeted runs; check now lists the entries (server-1 → camouflage:443 retransmissions). Fix: the reset aborts every TCP connection left (`ss -K`). Mutation: the code without the step is the before, which failed in 3 of 8 runs; with it, 5 of 5 passed (7463499b)
- 2026-11-19 merged origin/rewrite (TP-251, TP-248); README matrix paragraph re-applied on TP-251's text
- 2026-11-19 make lint, make test green on 27ba73b3; targeted matrix on 27ba73b3: longest lab 193 s, matrix 412 s, 88/88 cells, verdicts as before apart from the two chance cells
- 2026-11-19 full make lab-test on 27ba73b3 (lab commit): passed, RESULTS.md assembled, default stream 34m12s, over the 15m budget; box 1 left unticked (Notes). Not verified: wireguard × fully-encrypted's exemption in the full lab (a passing test's log isn't printed there)
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.5
- 2026-11-19 merged origin/rewrite (TP-245, TP-254 filed); README matrix paragraph merged with TP-245's rhythm text
- 2026-11-19 R1.1–R1.5 fixed (ea1ef19e). Mutations: held cells dealt like the rest (killed by TestRowLabs and TestRhythmRealTarget); the target's filter widened to every lab of the row, `^(udp|reality)(_lab_[0-9]+)?$` (TestRhythmRealTarget); every lab records the off cell (TestRowLabs); cells appended out of censorCases' order (TestRowLabs); matrixLabs without its sort (TestRowLabs); recordedTwice never finds (TestRecordedTwice); tcpAborted ignores what's left (TestTCPAborted)
- 2026-11-19 make lint, make test green on ea1ef19e; targeted default-stream matrix on ea1ef19e: 88/88 cells as expected, verdicts as on 27ba73b3 apart from wireguard × fully-encrypted (varies, exemption logged), wall 1654 s on a loaded machine (lab starts up to 13m41s); make lab-test-rhythm-real on ea1ef19e: both rhythm cells at real time, failed as expected, 577 s; reality lab 2 ×10 on ea1ef19e: 10/10 passed, no connection outlived an abort. No full lab (brief)
- 2026-11-19 filed TP-255 (reality × active prober scores pass on a short baseline); box 1 moved to TP-254, box 2 reworded
- 2026-11-19 has-errors → review
- 2026-11-19 merged origin/rewrite (TP-250, TP-252, TP-253); make lint, make test green on 30f61c51; targeted default-stream matrix on 30f61c51: 88/88 cells as expected, longest lab 259 s (https), matrix 564 s, no connection outlived an abort, verdicts as on 27ba73b3 apart from wireguard × fully-encrypted (varies, fail this time)
