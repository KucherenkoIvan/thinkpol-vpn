---
id: TP-248
title: "TestKillSwitchUnderSystemd split into parts that each take ≤ 60 s of lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-241]
refs: []
owner: agent-tp-248
branch: tp-248-killswitch-test-split
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). After TP-241 the test takes ~208 s (≈98 s lab start under load, ≈13 s systemd boot, ≈110 s for ~25 state changes); TP-241's box "kill-switch test ≤ 60 s" moved here.

## Scope
- Split by the behaviour each part proves (independent parts in parallel labs, or one lab with parallel subtests where state allows), keeping every assertion.

## Out of scope
The 3 s refusal limit's flake: TP-246.

## Acceptance
- [x] Each part ≤ 60 s in use. Evidence: the budget report. (TP-239's report isn't merged: each part logs its own in-use time; on the final code, 6 runs at load 7 to 31, at most 38.7 s; Notes.)
- [x] Every assertion of the original kept (list in Notes).

## Notes
- **How "in use" is measured.** TP-239's budget report isn't merged, so each part measures itself: it logs `in use` (from its lab being up until its body ends: setup, checks, failure dumps; the tear-down apart) and `after a lab start of` (the runner's shared overhead). The numbers below are from those log lines.
- **Before** (the original test with step timings, 5cb1ad81, load 5 to 11): lab start 16.4 s, then 90.9 s in use, of which 8.3 s setup (boot, space, server-1, service install) and 82.6 s for the steps: off 1.2 s, on and confined 6.1 s, allow-LAN 6.7 s, connect/disconnect 7.2 s, crash while on 13.6 s, stop/start 5.8 s, off under the space preset 2.2 s, everything connected 1.5 s, renewals 6.2 s, table repairs 7.9 s, crash under everything 13.4 s, disconnect 2.1 s, opt-out 5.1 s, uninstall 3.6 s.
- **After** (in use per part, from the parts' own log lines; load is the runner's 1-minute load average, sampled every 30 s):
  - final code, 1144c055, 6 runs, load 7 to 31: `down` 14.0 to 31.7 s, `crash-and-stop` 23.6 to 35.9 s, `live-agent` 20.9 to 38.7 s, `crash-posture` 25.7 to 37.1 s; lab starts 35 s to 3 min 9 s (lab-slot waits included).
  - 82e78180 (before the repair timing moved into the node), 12 runs, load 1.4 to 32: every part 20.6 to 37.2 s.
  - f788aaa2 (before the exec cuts), 10 runs, load 6 to 51: 17.3 to 45.9 s, except one run at load ~32: `down` 59.7 s, `crash-and-stop` 62.4 s, `crash-posture` 59.6 s. That run is why `confined`, `open`, `diagShows` and `crashHeld` now spend fewer serial execs, and why "off under the space preset" moved from `crash-and-stop` to `down`.
- **The split.** `TestKillSwitchUnderSystemd` has four parallel subtests, each with a lab of its own (`lab.StartOwnSlot`) and an agent set up afresh by `startKillSwitchLab` (the original's setup, unchanged, ending in the "disconnected" state check):
  - `down`: off once installed; on in place with the tunnel down; allow-LAN on and off; connected, the TUN passes; a disconnect keeps the switch; off while connected removes it, and a disconnect leaves traffic direct.
  - `crash-and-stop`: switch on, a crash while connected holds the table, the direct destinations expire, the restarted agent connects; a stop leaves the down shape and a start comes back connected.
  - `live-agent`: after a member's explicit `kill-switch off`, under "everything", the renewals and the table repairs.
  - `crash-posture`: after a member's explicit `kill-switch off`, under "everything", a crash holds the switch, a disconnect removes it, node.json's opt-out leaves traffic direct after a crash; then the uninstall, on an agent that has crashed and restarted, as in the original order ("whatever left it": uninstall also cleans a crashed run's trace, locks and stale sockets).
  `live-agent` and `crash-posture` start with an explicit `kill-switch off` because in the original they ran after `down`'s off: the device file's explicit false, not the node's default, is what the "everything" posture and the opt-out must hold against (internal/agent's package doc, "The kill switch").
  No two parts share a lab: none of them needs another's state, and any two together would come to over 60 s in use under load. The cost is 16 container starts instead of 4.
- **Fewer serial execs.** On a loaded runner each `docker exec` costs up to seconds, and that, not the kill switch, is where a part's time goes. So `confined` and `open` run their probes at once (each probe is a flow of its own, which the kill switch judges alone, and each is timed inside the node: ping's -W, nc's -w, curl's own time_total); `diagShows` reads the chains and sets at once after `diag`; `crashHeld` writes and reloads the hold drop-in in one exec, and removes it, reloads and restarts in another. No bound changed: curl's 3 s (by time_total) and 5 s, ping's 2 s, nc's 3 s, the 1.5 re-apply periods, every `Eventually` deadline, the 2 s/6 s timers.
- **The table repairs, timed by the node's clock.** In a 6-run batch on 82e78180, `live-agent` failed once: "the table removed from outside (2) was back after 4.07 s, want within 3 s". `backIn` deleted the table with one `docker exec` and polled `nft list table` with more, timing it all by the host's clock, so a loaded exec stretched the measured wait (TP-246's cause, in another check), and the gap before the next removal too, which made "removed again just after a re-apply" untrue. The four removals and waits now run in one exec, timed by `date +%s%N` in the node, and the bound is unchanged: the first back within 30 s, the other three within 1.5 re-apply periods (3 s).
- **Every assertion of the original, and the part that now holds it:**
  1. service installed: status "disconnected": every part (setup).
  2. "installed, off": no table, diag shows none, traffic direct (ping bound, TCP): `down`.
  3. `kill-switch on` prints "on, allow-LAN off (in place)", and `kill-switch` the exact line: `down`.
  4. "on, disconnected": table present, not connected; diag matches nft (chains, rule counts, TUN rule, set sizes); confined (foreign pings unanswered unbound and bound, both families; the entries answered; TCP refused; curl bound to eth0 refused within 3 s by curl's clock): `down`.
  5. allow-LAN on: foreign reachable, ping and TCP; allow-LAN off again: confined: `down`.
  6. connect and ping server-1; "on, connected": table connected, diag connected; disconnect: table present, not connected, confined: `down`.
  7. off while connected: no table, diag shows none; disconnect: traffic direct: `down` (was after the stop/start).
  8. crash while connected (SubState auto-restart with the restart held): table connected, the direct destinations expire, confined; restarted: connected, ping, table connected: `crash-and-stop`.
  9. stop: table present, not connected, confined; start: connected, ping, table connected: `crash-and-stop`.
  10. "everything, connected" (after a member's explicit off): table connected: `live-agent` and `crash-posture`.
  11. renewals: never expired, renewed at least twice and past a whole direct timeout; the direct destination bound to eth0 still answers: `live-agent`.
  12. the table removed from outside comes back within 30 s, three times more within 1.5 re-apply periods; then present and connected: `live-agent`.
  13. crash under everything, the switch explicitly off in the device file: table connected, expired, confined; restarted connected, ping; disconnect: no table, traffic direct: `crash-posture`.
  14. opt-out, the switch explicitly off in the device file: restart with node.json, "disconnected", connect, ping; crash: no table, traffic direct; restarted "connected": `crash-posture`.
  15. uninstall with the switch on and connected, after the crashes and restarts: table connected before, no table after, traffic direct: `crash-posture`.
  16. on failure, the agent's log and the ruleset in the test log: every part.

## Review findings
- [ ] R1.1 (should-fix) the uninstall ran in `live-agent`, on an agent that never crashed; moved to the end of `crash-posture`, after its crashes and restarts ("whatever left it").
- [ ] R1.2 (should-fix) `crash-posture` and `live-agent` started with kill_switch unset (the node's default), not a member's explicit false as in the original; each starts with `kill-switch off` again, Notes items 13/14 say so.
- [ ] R1.3 (should-fix) the repair clock started after `nft delete` returned; it now starts before the delete.
- [ ] R1.4 (nit) the `len(backIn) != 4` failure has a message of its own; the delete's stderr stays in the output.
- [ ] R1.5 (nits) the pointless `rm node.json` dropped; lab/README.md keeps the general rule, without naming this test.

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-248
- 2026-11-19 TestKillSwitchUnderSystemd split into four parallel subtests, each with a lab of its own (`lab.StartOwnSlot`) and logging its in-use time: `down`, `crash-and-stop`, `live-agent`, `crash-posture` (13f45d16); probes, diag reads and the crash hold in fewer serial execs, off under the space preset moved to `down` (82e78180); the table repairs timed by the node's clock (1144c055); lab/README.md "Writing a lab test" (f788aaa2)
- 2026-11-19 lab runs (targeted `make lab-gotest PKG=./lab RUN=TestKillSwitchUnderSystemd`, on a runner shared with other tickets' labs): baseline 5cb1ad81 (the original with step timings) passed, 16.4 s start + 90.9 s in use; f788aaa2 COUNT=10: 9 runs passed, in the 10th `down` and `live-agent` passed and the other two never got a lab slot before the 60 min test deadline (lab starts up to 9 min; nothing about the kill switch); 82e78180 COUNT=6 twice: 11 runs passed, 1 failed in `live-agent`'s host-timed repair check (4.07 s against 3 s), fixed in 1144c055; 1144c055 COUNT=6: 6 runs passed (959 s); e2558fb9 (after merging rewrite): passed, 90.5 s, parts 17.6 to 24.7 s in use; `make lint`, `make test` green on e2558fb9
- 2026-11-19 mutations (each in a scratch checkout of the branch, never pushed): E1, the docker exec stretched by `sleep 3.5` before curl inside it, the fix unchanged: `down` passes (curl's own time_total under 1 ms); E2, the same stretch with the refusal timed by the exec's wall clock (TP-246's cause back): `down` fails all 6 refusals, 3.8 to 5.2 s around curls of 0.14 to 0.21 ms; M2, the kill switch's TCP reset → drop (`refused()` in internal/dataplane/firewall/killswitch_linux.go): `down` fails all 6 refusals at curl's 5 s (the nc TCP checks alone don't catch it: a dropped connect is "not connected"); M3, the agent's re-apply ticker at 2 × the period: `live-agent` passes the renewals and fails all three repairs, back after 3.95 to 4.06 s against 3 s
- 2026-11-19 not verified: the in-use bound against TP-239's budget report (not merged) and inside a full lab (per the 2026-11-18 lab-runs rule, targeted runs only); the final code above load ~31. The split costs 12 more container starts per run (16 instead of 4), not measured in a full lab
- 2026-11-19 out of scope: under the shared load, lab starts waited up to 9 min for a lab slot, and a COUNT=10 batch lost its last two parts to the 60 min test deadline that way (lab slot cap, not this test)
- 2026-11-19 final head 833dd47d: `make lab-gotest PKG=./lab RUN=TestKillSwitchUnderSystemd` passed (128 s, parts 25.4 to 32.5 s in use), `make lint` and `make test` green
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.5, merge
