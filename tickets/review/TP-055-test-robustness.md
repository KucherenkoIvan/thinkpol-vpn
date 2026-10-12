---
id: TP-055
title: "Make tests robust under parallel lab load"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-002, TP-012]
refs: [DESIGN#censor-lab]
owner: "agent-flakes"
branch: "tp-055-test-robustness"
---

## Goal
`make lab-test` passes reliably while several agents run labs on the same host at once (host load around 28). Today several tests fail intermittently under load in code nobody changed and pass on a rerun, and every rerun costs a full lab run. Each flaky test either becomes deterministic, moves its performance-dependent threshold to `make lab-perf`, or (for statistical tests) uses enough samples that a false failure is negligible, without weakening what it proves.

## Scope
- Root-cause and fix the known flakes:
  - `internal/agent/supervisor` `TestSharedListenerThroughput` (24% loss vs its 20% functional limit in lab-test mode)
  - `internal/dataplane/netcfg` `TestDefaultRoute`
  - `internal/dataplane/transport/udp` `TestPaddingHidesPacketSizes`
  - `internal/dataplane/transport/transporttest` many-concurrent-links lost a datagram under `-race` (TP-010 note)
- Scan the rest of the tests for timing sensitivity (fixed sleeps, tight timeouts, exact counts over lossy paths, statistical thresholds with small samples) and fix what's found the same way.
- If a test was catching a real bug, fix the product and say so.
- Decide whether `make lab-test` should limit its own in-node package parallelism under high host load; document the decision.

## Out of scope
Earlier flakes already fixed: `TestWorkersAreSandboxed` (TP-054), `TestCommandStartsSealed` (TP-054), the agent map-watcher test (TP-017). Product areas being worked in parallel (TP-014 egress, TP-018 route table, TP-020 DNS) beyond their test files.

## Acceptance
- [x] every listed flake: cause found in the code, fixed (deterministic, perf-gated, or statistically sound), cause → fix in Notes, plus those added during the ticket (agent status, udp churn, netcfg snapshots, conformance waits)
- [x] scan of other timing-sensitive tests done; findings fixed or noted as fine (Notes, "Scan")
- [x] in-node package parallelism under load decided and documented: fixed `LAB_P` (default 4), not scaled by load (lab/README.md "Tests under load")
- [x] each fixed test run with a high `-count` inside lab nodes, green, with 8 CPU burners saturating the Docker VM (host load 22–28): `TestDefaultRoute`, `TestPaddingHidesPacketSizes`, `TestSharedListenerThroughput` 30/30 each; netcfg package 20/20; `TestAPeerMovesBetweenDevices` and the relay/exit tests 30/30; dataplane and agent packages 10/10; lab `TestShapingCapture` 5/5; every package 5/5 (`labctl gotest -count 5 ./...`)
- [x] host, under the same load: agent `TestADeviceConnectsAndDisconnects` 40/40 under `-race` (origin/rewrite: 2/40 fail); udp and supervisor conformance 8/8 under `-race`; supervisor flood, stuck-worker, bad-credential tests 20/20 under `-race`; watcher, retry, shared-status, blobs, udp replay and churn tests 20–50 runs each; whole repo 3× under `-race`
- [x] one full `make lab-test` green (at accc627) while another lab (`make lab-up` under `THINKPOL_LAB_PROJECT=tp055-load`, its device-a running 8 busy loops) was up
- [x] `make lint`, `make test` green

## Notes
Each flake: cause → fix. Product code is unchanged: every cause was in a test, except one status glitch noted at the end.

- **supervisor `TestSharedListenerThroughput`** (24% loss vs 20%): in `make lab-test` it still ran the perf load, 100 Mbit/s paced into a supervisor pinned to one CPU, and on a saturated VM that CPU simply isn't there. → `make lab-test` no longer measures. It sends 2000 echoes through the handoff with at most 32 in flight, which none of the path's queues (public socket, data socket, worker queue) can overflow, and requires every one back. That is stricter than the old 20% limit. Targets and figures run only under `make lab-perf`. lab/README.md updated.
- **netcfg `TestDefaultRoute`**: the kernel flags routes `RTNH_F_LINKDOWN` from its linkwatch work after the carrier change, up to a second (more under load) after `ip link set ... down` returns, so `DefaultRoute` could still see the route as usable. → `awaitLinkDown` polls until both default routes through the veth carry the flag.
- **netcfg snapshots** (`TestApplyThenCloseRestoresEverything`, `TestFailedUpdateKeepsThePreviousConfig`, `TestReApplyRepairsOutsideChanges`, found in the sweep and reported by other agents): IPv6 duplicate address detection runs from a work queue, and only when it ends does an address (the overlay's, and the fe80 one after link up) lose its tentative flag and get its local route in table 255. A snapshot right after `Apply` raced it. → `snapshot` first `settle`s: no tentative address, and every IPv6 address on an up link has its local route.
- **netcfg `changes()`**: counted netlink events for a fixed 300 ms after `f`. A late event was missed, so "made no change" passed falsely and "made changes" failed falsely. → After `f` it makes one address and one route change of its own, on a dummy link it then deletes, and counts what each (in-order) subscription delivers before them.
- **udp `TestPaddingHidesPacketSizes`** (`a 82-byte packet went out as 156 bytes, want the 256 bucket`, reproduced under load): the test sets the shaped table after the listener starts, and `udp.Listener` takes table changes in a background goroutine. The first reply could be sealed with the old (unshaped) entry. → It waits until the listener's flow holds the shaped entry, as `TestSettingsChangeKeepsTheLink` does. The random-padding burst of 100 goes in batches of 10 the tap's socket has room for. The `≥ 50 of 100 distinct` check has a false-failure probability of about 5e-23 (in a comment).
- **transporttest `ManyConcurrentLinks`** (lost a datagram under `-race`, TP-010): 32×17 single-shot ping-pongs over loopback UDP, and a socket buffer overflowing while the reader is held up loses one. → Each round is resent after 1 s as a fresh packet, so each echo says which copy came back. Late echoes count as delivered (drained at the end), and the test fails if more than 5% of packets never came back. That still catches a lossy transport, and a stall doesn't count as loss.
- **transporttest `ShapingRefused`**: `table.Set`, a 20 ms sleep, then a single hello. Listeners apply the change in the background, and memory decides at dial time. → `connectAdmitted` redials until accepted, with growing patience. The other post-`Set` sleeps (`TableChangeKeepsLinks`, `ShapingChange`) can only make those tests pass early, never fail, so they stay.
- **conformance timeouts on a loaded host** (reported): not reproduced in 8 runs of the udp and supervisor suites under `-race` and load, on origin/rewrite or here. The two waits that can expire under load (single-shot echoes, the 20 ms sleep before one hello) are fixed above.
- **agent `TestADeviceConnectsAndDisconnects`** (reported 5/40 under -race; 2/40 here on origin/rewrite, 0/40 fixed): after a map without the node, it waited for any `Connecting`. `runner.stop()` publishes `engine = nil` before `publish()` sets the new version and `removed`, so a reader sees "connecting, old version, not removed" for a moment. → The test waits for version 4 and `Connecting` together. **Product follow-up (not done here):** `stop()` should publish the whole state, not only `engine = nil`, so status never shows that mixed state. TP-020 edits the lines around that `report.set`, so it is left to land after TP-020 merges: **TP-056** (backlog, depends on TP-020).
- **dataplane `TestAPeerMovesBetweenDevices`** (sweep: 10 s without a reply): the test path timings closed a link after 150 ms without a probe reply (and gave dials 150 ms). A stalled scheduler does that alone, and what is sent meanwhile is dropped, a WireGuard handshake included, which is retried only after WireGuard's 5 s. → `fastPaths` (dataplane, agent) probe every 300 ms and declare a link dead after 1 s, still six times faster than the defaults. Package run times are unchanged.
- **udp `TestSenderChurnIsBounded`** (`200000 new senders took 3.02s` under race and load): normally 0.1 s, 1.5 s under the race detector. → The 2 s bound holds without `-race` only (`raceEnabled`, build-tagged), where it still catches a per-eviction cost that grows with the history.
- **agent `TestAFailedApplyIsRetried`**: bounded the retry at 5 × 300 ms, including log polling. → The bound is `RetryAfter/2`: it still proves the retry runs on the data plane's own interval, not the 5 s default.
- **supervisor `TestASourceFloodStallsNoOtherSpace`**: a 10 ms median round trip is a speed, and scheduler latency at load ~28 exceeds it. → The bound is the ping's resend interval (50 ms): above it, most pings were stuck long enough to be resent, which is a stall.
- **supervisor `TestAStuckWorkerStallsOnlyItsSpace`, `TestBadCredentialsNeverReachAWorker`**: bursts over the shared socket could overflow it. → The live space's probe is resent until it arrives; forgeries go in batches of 16.
- **agent watcher, localapi shared status, blobs stalled transfer, udp replay tests**: fixed sleeps before assertions. → They wait for the warning, the trickling transfer's start (a channel) or the counters. The shared-status bound allows one read per `minWatchInterval` the loop actually took.
- **lab `TestShapingCapture`**: the router captured each datagram twice, 200 µs apart, into a ring of about 500 frames, so a tcpdump held up for about 50 ms dropped frames. → Only the copy leaving the router is captured (`outbound`), and the sender paces at 1 ms: about half a second of tolerance, same assertions.
- **Tooling:** `labctl gotest -count n -timeout d`, `make lab-gotest ... COUNT=n`, `make lab-test LAB_P=n`. lab/README.md gets a section, "Tests under load", with the rules above.
- **Parallelism decision:** no automatic throttling. The load that hurts comes from other runs, which a run can't control; the Docker VM's load isn't the host's load average; and `THINKPOL_LAB_MAX_LABS` already caps labs across runs. Tests must hold up regardless, and `LAB_P` lowers it by hand.
- **Scan** (fixed sleeps, short deadlines, exact counts over lossy paths, statistics): fixed as above. Assessed and left alone, because they passed every load sweep: the path package's fake-clock tests (5 slack ms per 100 fake ms, designed for race stalls) and its `fastOptions` wall-clock tests; `TestThinkpolWorkerCommand` and `TestDeafWorkerHoldsNothingUp` stop timeouts; `TestKilledWorkerRestartsAlone`'s exact start count; the blob tests' 100 ms overlay-address lookup; `TestM0`'s ping bursts (kernel forwarding, 2 s per reply); `testRevocationRacingDial` and `testCloseRacesLeakNothing`. Quiet windows that only check absence can't fail falsely under load.

## Review findings
- [x] ManyConcurrentLinks tolerated 5% loss, which could hide a transport losing ~2% per direction → an absolute bound, `maxLost = 3` round trips of 544+ that never come back, with a comment (a transport losing 1% per direction, about 11, fails). The resend stays.
- [x] Non-test code changed: only `Makefile`, `lab/labctl/main.go`, `lab/README.md`, and `internal/dataplane/transport/transporttest/transporttest.go`. The last is the conformance-suite package, imported only by `_test.go` files. No product code changed.
- [x] The runner.stop() status-order follow-up is ticket TP-056 (backlog, depends on TP-020).

## Log
- 2026-10-12 created in in-progress — owner: agent-flakes, branch: tp-055-test-robustness
- 2026-10-12 in-progress → review — make lint, make test, make lab-test green (with a second, CPU-saturated lab up); fixed tests 20–50× in lab nodes and under -race
- 2026-10-12 review findings: ManyConcurrentLinks loss bound made absolute (≤ 3); non-test diff confirmed; TP-056 created for the status-order follow-up
