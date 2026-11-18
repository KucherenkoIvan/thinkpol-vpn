---
id: TP-239
title: "Long-wait lab tests run in their own stream, with a time budget"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-238, TP-223]
refs: []
owner: "agent-tp-239"
branch: "tp-239-long-wait-stream"
---

## Goal
The censor matrix's rhythm holds (7.5 min each) and the 450 s long probe make every full lab wait on them.

The owner (2026-11-16): a full lab must take at most ~15 minutes on the remote runner; waits only where no watcher can tell, otherwise a sped-up clock; long-wait tests in a separate stream that never blocks others; everything that can run in parallel must. Measured on the remote runner (2026-11-16): the `lab/` package alone took ~46 min; the host-wide subnet allocation lock is held for each lab's whole `docker compose up --wait` (10–45 s per lab), so lab starts are serialized across every run (~92% busy); non-parallel teardown tests add a ~14.5-minute serial prefix before parallel tests resume.

## Scope

## Out of scope

## Acceptance
- [x] The long-wait tests (the rhythm holds, the long probe, any other test that waits minutes on real timers; list in Notes) run in their own stream, `make lab-test-long`, which runs alongside the default stream and never blocks it.
- [ ] `make lab-test` runs both streams at once; the default stream alone can run on its own.
- [x] A budget check fails the default stream if it runs past 15 minutes on the remote runner (the limit and how it's measured documented in lab/README.md).
- [x] Full-lab wall time before and after, in Notes.

## Notes
**The long-wait tests**, the lab tests that wait minutes on real timers:
- `TestCensorMatrix`, reality × `wireguard-rhythm`: holds the tunnel 450 s (7.5 min), in use, then probes. The reality row took about 865 s in one lab before (TP-240).
- `TestCensorMatrix`, udp × `wireguard-rhythm` (the control): the same 450 s hold.
- "The 450 s long probe" is the probe that ends those holds (TP-223's traces: "until the probe at 450 s"), not a separate test. The prober's own waits are watchers bounded at 2 min (`settleWithin`, `awaitJudgments`).
- Nothing else waits minutes on a timer. I grepped every test's sleeps and `time.After`s (lab/ and in-node packages) and found only deadlines and polls; the longest fixed sleep is 45 s (`killswitch_test.go`, TP-241's). The slowest tests in the budget reports below are slow on lab setup and load, not on timers.

**No sped-up clock for the holds.** wireguard-go's `RekeyAfterTime` (120 s), `RekeyTimeout` and `KeepaliveTimeout` are Go constants (`device/constants.go`), and the module judges how real rekeys recur on the wire. A faster clock would need a patched wireguard-go at both ends and would show the module a rhythm stock WireGuard never has, so the cell would stop proving anything about it. The hold is already about three rekeys plus jitter, the least the module needs. No change proposed. The prober has no long interval to speed up.

**Design.**
- `THINKPOL_LAB_STREAM` (`lab.Stream()`) is `default`, `long`, or unset; unset runs everything whole, as a plain `go test` does.
- In the long stream, `TestCensorMatrix` runs only the held cells (`heldCell`: the case holds and the row has a hold). Each held row gets a `lab.Upstream()` lab of its own, and its `off` cell runs again first as the gate. That is two more labs per full lab, 14 more container starts. The default stream runs every other cell, including the held rows' other cells.
- Each stream writes its share (cells, expected count, failed or not) to `THINKPOL_LAB_RESULTS_DIR`, the run's temp dir. Once both streams have ended, `make lab-test` runs `TestAssembleCensorMatrix`. It writes RESULTS.md only from two complete shares with no failure that together cover every cell exactly once. A share that is missing, short, failed or holds an errored cell fails the run.
- `make lab-test` runs `lab-streams LAB_STREAMS='default long'`; `make lab-test-default` and `make lab-test-long` run one stream each. The long stream runs `-run $(LAB_LONG_TESTS)`, today `^TestCensorMatrix$`.
- The budget is `LAB_BUDGET` (default 15m, settable from the environment). It is wall time from the recipe's start to the end of the default stream's last phase, with the labctl build, the stale-lab clean-up and every lab's setup included. `labctl budget` prints the stream's time on every run. Over budget, it fails and lists the 10 slowest tests from the times files: `labctl testjson` turns go test -json into plain output plus per-test times for `lab/`, and `labctl gotest -times` covers the node phase. The long stream's time is printed when it ends.
- Also fixed: `make lab-gotest` now takes `LAB_TIMEOUT` from the environment or the command line (labctl's run bound grows with it, `gotestRunFor`), and it takes `SKIP=` (`labctl gotest -skip`).

**Wall times** (full `make lab-test`; before the lab-speed tickets a clean full lab took 2823 s):

| commit | wall | default stream | long stream | conditions | failures |
|---|---|---|---|---|---|
| 95794ac3 (base, one stream) | 3446 s | n/a | n/a | beside other full labs | TestKillSwitchUnderSystemd, the openvpn-tcp row (650 s), dns settle flake |
| b22873ab | 3248 s | 54m6s (over budget) | go test 958 s | heavy load | two lab setup stalls, dns flake, reality TestConformance/Delivery |
| 94c9fc5f | 3685 s | 1h0m28s | 10m6s | concurrent full labs starved the lab slots | lab-slot waits only, not evidence |
| ede0b69c | 2893 s | 48m12s | 16m5s, passed | one other full lab; 1-min load 8.5 to 31.5 | 3 lab-slot waits (pass when re-run targeted), TestBlobDistribution (TP-244) |
| **07d9ec09 (final)** | **2141 s** | **35m40s, fails its 15m budget** | **12m19s, passed** | no other full lab; 1-min load 5.6 to 27.9 | TestKillSwitchUnderSystemd (TP-246), a dns resolv.conf rename test (TP-235's family): both pass when re-run targeted |

On the final commit both streams ran, and RESULTS.md was assembled whole from both (90 cells; the reality and udp rhythm cells came from the long stream). `make lab-test-long` alone at ede0b69c took 977 s and passed.

**The default stream does not fit 15 minutes yet.** With this branch merged, every full lab fails on its budget until the other lab-speed tickets cut the default stream. That is the budget doing its job. A machine can set `LAB_BUDGET` in its environment meanwhile. In the final run the budget report names TestLabStartsOverlapOnDistinctSubnets (10m), TestCensorMatrix/reality (8m19s for its unheld cells), the openvpn-tcp, random-tcp, openvpn-udp and relay-tcp matrix rows (5m22s to 6m38s), TestCensorReplaysClientHello (6m6s), the dns and firewall node packages (about 6m each) and TestKillSwitchUnderSystemd (5m54s).

`make lab-test-default` has not yet run on its own in a full lab. It is the same recipe with `LAB_STREAMS=default`; `make lab-test-long` alone did run, and passed.

## Review findings
Review round 1. The split and the assembly are sound; the problems are the TP-242 merge, the output filter and robustness.
- [ ] R1.1 (blocker for the merge) Makefile: RESULTS.md assembly runs only when the phases are exactly "lab node long" and the fallback exits 0; with TP-242's harness phase the obvious merge silently stops writing RESULTS.md. Key the assembly on the requested streams (LAB_STREAMS has both) and fail when both were asked for and assembly didn't run or `go test` matched no test. In the merge: the default stream's go test keeps TP-242's `-skip '$(LAB_HARNESS_RUN)'`; the harness phase's status is waited on and fails the run; the harness phase counts toward the default stream's budget and writes times the budget report can name.
- [ ] R1.2 (should-fix) Makefile: `go build -o "$labctl" ./lab/labctl` stamps VCS info, so TP-243's node-phase cache (keyed on labctl's binary hash) misses on every commit and lab-test no longer shares records with lab-gotest (`go run`). Build with `-trimpath -buildvcs=false` (as lab/prepare.go does) and use the same build in lab-gotest. Show a docs-only commit keeps node packages cached.
- [ ] R1.3 (should-fix) lab/streamtime.go: the JSON→text filter prints passing subtests' output when a top-level test fails (TestCensorMatrix: every cell's log), so the 1 MiB head+tail cut can drop the failing cell's error. Keep logs per full test name; drop a test's log when it passes or skips; on a subtest failure append its log to its parent's; drop `=== RUN/PAUSE/CONT/NAME` lines; sort keys in the package-end flush; keep an unended test's output whole. Fix TestFilterTestJSON's `want` and the doc comment/README claim.
- [ ] R1.4 (should-fix) README/Makefile: nothing enforces "a long test skips in the default stream". Add `lab.LongTest(t)` (skips outside the long stream) and a unit test that LAB_LONG_TESTS names exactly the tests that call it; run the long stream over ./lab/... so a long test outside ./lab is reached.
- [ ] R1.5 (owner default) every full lab now fails its 15m budget, and the lab is the only CI. Keep the budget failing the run, but make it separable: tests passed and only the budget failed → a distinct exit code and a last line "lab-test: tests passed, OVER BUDGET (<wall> > <budget>)"; tests failed → say so first. Document it.
- [ ] R1.6 (should-fix) LAB_BUDGET=0, negative or empty: 0/negative silently turn the check off and empty makes -budget swallow the next argument. Reject empty and negative; 0 means off only if documented.
- [ ] R1.7 (should-fix) labctl gotestRunFor: max(60m, timeout+15m) bounds the whole run, but with -tagged the node run and the host `go test -tags lab` run one after the other, so the host run is cut early; `-timeout 0` is capped at 60m. Bound each phase by its own timeout (or 2×timeout+15m when tagged), no bound when timeout is 0; fix the comment.
- [ ] R1.8 (should-fix) Makefile: assembly runs `go test` ~40 min later against the checkout as it is then; an edit or branch switch mid-run builds a different binary. Build the lab test binary once per run and use it for both streams' matrix runs and the assembly; record the commit (HEAD plus dirty flag) in each share and refuse mismatches; check share.Stream against the file it came from.
- [ ] R1.9 (should-fix) Makefile: the EXIT trap only removes the temp dir; on Ctrl-C the labs stay up. Trap INT/TERM so the EXIT path runs `labctl down -run "$run"` (unless THINKPOL_LAB_KEEP) once the run is known.
- [ ] R1.10 (doc) README "never in its way": the long stream takes two lab slots from the shared cap for ~12 min; say it shares the cap.
- [ ] R1.11 (nits) gotest.go: skip 0.000 time lines for packages not built or failed in prepare; the slowest list shows a parent and its subtests with the same time: leave out or mark parents; TestGotestSkipAndTimes trims the user's real cache: set LAB_NOCACHE; matrixstreams_test.go: a case that reaches "cell in neither share", and a unit test for writeMatrixShare (mutations "Failed always false", "long stream keeps its off cells").
- [ ] R1.12 (ticket) `make lab-test-default` alone once in a full lab on the final commit, and one full `make lab-test` on the final commit; record wall times, the budget report's slowest tests, and whether RESULTS.md assembled whole. In Notes, state that the reality row's ~8m19s of serial cells (without the hold) alone makes 15 minutes unreachable, as the next lab-speed item.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority)
- 2026-11-18 backlog → in-progress, owner: agent-tp-239
- 2026-11-18 built on TP-243's branch (since merged) and rewrite: streams (`THINKPOL_LAB_STREAM`, `make lab-test-default`/`lab-test-long`/`lab-test`), the matrix's held cells in the long stream with a lab per held row, shares assembled into RESULTS.md (`TestAssembleCensorMatrix`), `LAB_BUDGET` with a slowest-tests report (`labctl testjson`, `labctl budget`, `gotest -times`), `lab-gotest` honouring LAB_TIMEOUT and SKIP (`gotest -skip`); lab/README.md "Streams"
- 2026-11-18 mutations, each failing its test: pass output printed (TestFilterTestJSON), skip output kept (TestFilterTestJSON), no flush at EOF (TestFilterTestJSONUnendedAtEOF), budget doubled (TestCheckBudget), `-skip` not passed (TestGotestSkipAndTimes), times only for cached (TestGotestSkipAndTimes), times lost when a lab fails (TestGotestTimesWhenALabFails), missing share not reported (TestAssembleMatrix), `inStream` flipped (TestAssembleMatrix)
- 2026-11-18 full lab runs found two bugs, both fixed: the long stream's time was taken when the default stream ended, and the node phase wrote no times when a lab failed to start
- 2026-11-19 `make lint`, `make test` green at 07d9ec09; final full lab at 07d9ec09: 2141 s, default stream 35m40s (fails its 15m budget, as designed), long stream 12m19s passed, RESULTS.md assembled from both; TestKillSwitchUnderSystemd and the dns rename test failed there and pass when re-run targeted
- 2026-11-19 not verified: `make lab-test-default` alone in a full lab (its acceptance box stays open). Out of scope: the default stream is about 2.4x its budget, and TestCensorMatrix/reality's unheld cells take 8m19s
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.12
