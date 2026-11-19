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
- [x] The owner's decision recorded (owner, date).
- [x] udp × fully-encrypted still expects `fail`; a `partial` there is reported as "KNOWN FLAKE (TP-236): …" in the test output and RESULTS.md's cell and doesn't fail the run; a `pass` there still fails it; every other cell is unchanged (unit test of the scoring, mutation-checked).
- [x] A known flake that occurs is counted in the run's summary line.
- [x] lab/README.md says what the marker means, which cell carries it and why.
- [x] `make lint`, `make test` green; the udp row runs once in the lab (`make lab-gotest PKG=./lab RUN='TestCensorMatrix/^udp$$'`).

## Notes
- Decision (owner, 2026-11-19): option 3 + mark the test as known flake: keep expecting `fail`, don't score the known chance from logged evidence, don't change the udp transport, and mark the cell a known flake.
- How: `censorCase.flakes` marks udp in the fully-encrypted case (lab/results_test.go); `censorCase.verdict` accepts a partial there, starting the detail with "KNOWN FLAKE (TP-236): …", and nothing else; `checkMatrix` refuses a flake on a row its case doesn't expect to fail. `knownFlakes` sums them up ("KNOWN FLAKES: n (cells)") in the matrix's log, the assembly's log and RESULTS.md's header, and `make lab-test`'s last line repeats it (Makefile, from the assembly's output).
- Not run: a full `make lab-test` (the brief asked for none; the orchestrator runs full labs on rewrite after merges). A real partial in the lab wasn't seen (about 1 run in 120); the unit test covers its scoring and summary.
- Rejected: scoring the cell from logged evidence (the matrix accepting a partial only when the verdict log shows each crossing flow was the first judged on its pair and passed a named exemption); padding udp's first datagram (see Out of scope).

## Review findings
- [x] R1.1 (should-fix, all reviewers): the count reached `make lab-test`'s last line only when both streams ran and the assembly passed. — Each stream lists its known flakes next to its share (`flakesFile`, `writeMatrixShare`, lab/matrixstreams_test.go:38, :73), whether or not its matrix failed; the Makefile counts them after the phase loop, outside the assembly (Makefile:253), so every last line carries `KNOWN FLAKES: n (…)`, `lab-test-default`/`-long` and FAILED runs included. The assembly's log line went (nothing greps it now). lab/README.md's sentences fixed.
- [x] R1.2 (should-fix): the call site wasn't tested. — The cell's finish is `finishCell` (lab/results_test.go:702), which runCell calls (:224) and TestKnownFlake drives through a recording test (`recordingTB`), checking its errors and log line.
- [x] R1.3 (should-fix): the RESULTS.md header line and the stream's count could be deleted with everything green. — `resultsMarkdown` (lab/results_test.go:1969, split out of writeResults) is checked to say `KNOWN FLAKES: 1 (udp / fully-encrypted).` and nothing without a flake; TestWriteMatrixShareFlakes checks the stream's list. New TestKnownFlake cases: udp's `error` fails, udp's partial where the case wants `pass` fails; every failure and checkMatrix's refusal matched by their exact text.
- [x] R1.4 (docs): docs/design/lab.md:25 and lab/censor/doc.go:653 record the owner's exception (udp × fully-encrypted, known flake, owner 2026-11-19); lab/README.md "Known flakes" says the same flake in consecutive runs is a regression, not chance.
- [x] R1.5 (nits): the doc comment at lab/results_test.go:28 re-wrapped; a comment at the marker (lab/results_test.go:729) says it assumes a cell sees both families.

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 rescoped to the owner's decision (option 3 + known flake); needs_human dropped
- 2026-11-19 backlog → in-progress, owner: agent-tp-250
- 2026-11-19 udp × fully-encrypted marked a known flake (7db2706f): verdict, knownFlakes, checkMatrix's check, RESULTS.md header, make lab-test's last line, lab/README.md "Known flakes"
- 2026-11-19 TestKnownFlake (udp's partial reported and counted, not failed; its pass, random-tcp's partial in the same case and udp's partial against ip-blocklist failed; only udp × fully-encrypted marked; a flake on a row not expected to fail refused) and the matrix's unit tests pass. Mutations, each caught: a non-fail result accepted as the flake (udp's pass); the flake applied to any row; the mark left off the detail; knownFlakes counting nothing; checkMatrix's flake check removed; a second cell marked a flake
- 2026-11-19 make lint, make test green on 7db2706f; make lab-gotest PKG=./lab RUN='TestCensorMatrix/^udp$$' passed on 7db2706f (617 s; fully-encrypted scored fail, no flake this run)
- 2026-11-19 no full make lab-test (not asked by the brief); a real partial in the lab not seen (about 1 run in 120)
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.5, merge
- 2026-11-19 R1.1–R1.5 fixed (c530a8f0): the streams list their known flakes and make lab-test's last line counts them whatever ran; finishCell, resultsMarkdown; TestKnownFlake's new cases; TestWriteMatrixShareFlakes; docs. Mutations, each caught: finishCell comparing result != want instead of verdict; finishCell logging nothing; RESULTS.md's KNOWN FLAKES line dropped; the flake accepted whatever want is; the flake accepting an error too; checkMatrix's flake check removed; the stream's flakes list not written
- 2026-11-19 the Makefile's count checked by a shell simulation of its line (a flake in the default stream with or without the long one's list, none, no list at all: "FAILED: lab; KNOWN FLAKES: 1 (udp / fully-encrypted)", "passed; KNOWN FLAKES: 1 (udp / fully-encrypted)", plain lines without one); no real partial in the lab seen
- 2026-11-19 make lint, make test green on c530a8f0; make lab-gotest PKG=./lab RUN='TestCensorMatrix/^udp$$' passed on c530a8f0 (fully-encrypted scored fail, no flake this run)
- 2026-11-19 review → done (merged)
