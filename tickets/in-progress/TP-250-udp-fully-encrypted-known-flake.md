---
id: TP-250
title: "udp × fully-encrypted is marked a known flake"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-236]
refs: []
owner: "agent-tp-250"
branch: "tp-250-udp-fe-known-flake"
---

## Goal
A flaky cell costs a whole lab re-run, and the owner wants a full lab within about 15 minutes on the remote runner (2026-11-16). The censor matrix's udp × fully-encrypted cell expects `fail`, but TP-236 showed a real fully-encrypted censor lets about 1 run in 120 through: a new client/server pair's first datagram passes one of Wu et al.'s exemptions by chance (~1/175 for an 84-byte datagram more than half printable, ~1/383 for udp's printable connection id), and the censor judges each new pair afresh, so the cell then scores partial. When this is done, that cell still expects `fail`, and its chance partial is reported as a known flake instead of failing the run.

## Scope
- The matrix's expectations (lab/results_test.go) mark udp × fully-encrypted a known flake, with its reason and rate (TP-236; ~1 in 120; a new client/server pair judged afresh).
- A `partial` in that cell is reported as "KNOWN FLAKE (TP-236): …" in the test output and in RESULTS.md's cell, and doesn't fail the run by itself.
- A run's summary line counts the known flakes that occurred.
- lab/README.md: a short paragraph on known flakes.

## Out of scope
- Scoring the cell from logged evidence (the verdict log's exemption): rejected by the owner (2026-11-19).
- Padding udp's first datagram: rejected (changes the shipped transport for a lab artifact and can't remove the connection-id chance).
- Any other cell: unchanged.

## Acceptance
- [ ] The owner's decision recorded (owner, date).
- [ ] udp × fully-encrypted still expects `fail`; a `partial` there is reported as "KNOWN FLAKE (TP-236): …" in the test output and RESULTS.md's cell and doesn't fail the run; a `pass` there still fails it; every other cell is unchanged (unit test of the scoring, mutation-checked).
- [ ] A known flake that occurs is counted in the run's summary line.
- [ ] lab/README.md says what the marker means, which cell carries it and why.
- [ ] `make lint`, `make test` green; the udp row runs once in the lab (`make lab-gotest PKG=./lab RUN='TestCensorMatrix/^udp$$'`).

## Notes
- Decision (owner, 2026-11-19): option 3 + mark the test as known flake: keep expecting `fail`, don't score the known chance from logged evidence, don't change the udp transport, and mark the cell a known flake.
- Rejected: scoring the cell from logged evidence (the matrix accepting a partial only when the verdict log shows each crossing flow was the first judged on its pair and passed a named exemption); padding udp's first datagram (see Out of scope).

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 rescoped to the owner's decision (option 3 + known flake); needs_human dropped
- 2026-11-19 backlog → in-progress, owner: agent-tp-250
