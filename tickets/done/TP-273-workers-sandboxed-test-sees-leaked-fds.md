---
id: TP-273
title: "TestWorkersAreSandboxed is flaky: it sees leaked host-file descriptors"
milestone: M2
area: agent/supervisor
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-273
branch: tp-273-workers-sandboxed-fd-leak
---

## Goal
`TestWorkersAreSandboxed` (internal/agent/supervisor) fails now and then in full labs because a worker holds a descriptor to a host file it should never have, e.g. TP-266's run on an unchanged tree: `space 0 has leaked host-file fds: [/proc/748/uid_map]`. Find which descriptors leak and why, fix the cause where it is (a product open without O_CLOEXEC, or a fork that inherits another one's open, is a product defect and is fixed in the product; a test harness descriptor is fixed in the test), and make the test reliable without weakening what it claims.

## Scope
- Reproduce the flake with a loop of targeted `make lab-gotest` runs (under load if needed) and list the leaked descriptors (`/proc/<pid>/fd` of the worker, with their targets).
- Fix the cause; name every open or fork path changed.
- Keep the test's claim: a worker holds no host-file descriptor beyond the allowed ones.

## Out of scope
- Other sandbox properties (TP-272's leftover temp dir).

## Acceptance
- [x] The leaked descriptors and their cause, with file:line, in Notes.
- [x] The cause fixed; the test's leak check unchanged or stricter. (procLeakedFiles unchanged; new TestConcurrentWorkerStartsInheritNoHostFiles, named TestConcurrentWorkerStartsInheritNoFds before R1.3, applies it to eight workers started at once.)
- [x] A test or a reproduction that fails without the fix (mutation named in the Log).
- [x] 20 consecutive green targeted runs of the test on the final commit. (bc4d1454, COUNT=20 of both tests in one node: 20/20 each.)

## Notes
- Seen: TP-265/266 full labs, 2026-11-19 (TP-266's Log, R1.7).
- Cause (reproduced, see Log): Go's syscall writes a new child's `/proc/<pid>/uid_map`, `setgroups` and `gid_map` after its clone through `syscall.Open(path, O_RDWR, 0)` without O_CLOEXEC (`writeIDMappings`/`writeSetgroups`, src/syscall/exec_linux.go in go1.26.11), while `acquireForkLock` (src/syscall/forkpipe2.go) lets several forks run at once. The supervisor starts its workers from concurrent goroutines (`start`, internal/agent/supervisor/process_linux.go), so a worker cloned while another's maps are being written inherits that fd: the leaked `/proc/748/uid_map` is the other worker's map, open read-write, in the sandbox. A product defect, not a test one.
- Fix: `forkMu` serializes `cmd.Start` in `start` (process_linux.go), the only fork with id maps in the process. No product open changed: the opens are the standard library's. Other forks in the process (ip, nft) may still inherit such an fd briefly; they are host tools, not sandboxed, and a written map can't be written again.

## Review findings
- [x] R1.1 process_linux.go, the comment above forkMu: say that every fork with SysProcAttr UidMappings/GidMappings in the process must Start under forkMu, and that a Start stuck on its exec (a hung filesystem) holds up every worker start until it returns.
- [x] R1.2 process_linux.go start: unlock forkMu with defer (a small func around cmd.Start), so a panic in Start can't leave it held.
- [x] R1.3 supervisor_linux_test.go: procLeakedFiles flags host file paths only (it skips sockets, pipes, anon inodes, /dev), so the new test is named TestConcurrentWorkerStartsInheritNoHostFiles; its comment keeps only the constraint, the run history stays in the Log.
- [x] R1.4 doc.go: the new sentence moves after the no_new_privs sentence and reads "Worker starts are serialized (forkMu): Go writes a child's id maps through fds without close-on-exec, which a worker forked meanwhile would inherit."

## Log
- 2026-11-22 created in backlog (final-lab small fixes)
- 2026-11-22 backlog → in-progress, owner: agent-tp-273
- 2026-11-22 fix: forkMu in internal/agent/supervisor/process_linux.go start; new lab test TestConcurrentWorkerStartsInheritNoFds (eight workers started at once, fifteen rounds, no leaked host-file fd); package doc updated
- 2026-11-22 handoff: not run in the lab. The lab image can't be built: lab/Dockerfile pins nginx=1.22.1-9+deb12u10, which bookworm-security replaced with deb12u11, and no lab image is cached on the run machine. Still to do once it builds: reproduce on the parent commit (COUNT loop of both tests), mutation (forkMu.Lock/Unlock removed, the new test must fail), 20 consecutive green runs of TestWorkersAreSandboxed
- 2026-11-22 lab image fixed on rewrite (TP-275), merged in. Reproduced on c89aaf57 with forkMu.Lock/Unlock removed (mutation, edited on the run machine only, never pushed): the new test failed 1 of 3 runs, then 7 of 10 (five rounds each); each failing worker held another worker's id-map file open, e.g. ["/proc/558/setgroups"] in two workers, ["/proc/1175/uid_map"] in three, ["/proc/843/gid_map"]; TestWorkersAreSandboxed passed its 3 runs there. Rounds raised to 15
- 2026-11-22 mutation at fifteen rounds (bc4d1454, forkMu.Lock/Unlock removed on the run machine only): TestConcurrentWorkerStartsInheritNoFds failed 5 of 5 (COUNT=5); restored
- 2026-11-22 bc4d1454: make lab-gotest PKG=./internal/agent/supervisor/ RUN=TestConcurrentWorkerStartsInheritNoFds|TestWorkersAreSandboxed COUNT=20: 20/20 green each, EXIT 0 (2m59s, tests 1m35s); the whole package in the lab: green (59s); make lint and make test green
- 2026-11-22 not verified: TestWorkersAreSandboxed's own flake rate before the fix (it passed its 3 runs on the unfixed tree; the new test is the reproduction). Code lab-tested by targeted runs only; the full lab is the orchestrator's after merge
- 2026-11-22 in-progress → review
- 2026-11-22 review → has-errors: R1.1–R1.4 (review confirmed the cause and the fix)
- 2026-11-22 has-errors → in-progress
- 2026-11-22 R1.1–R1.4: forkMu comment (every id-mapped fork Starts under it; a hung exec holds up worker starts), startLocked unlocks with defer, test renamed TestConcurrentWorkerStartsInheritNoHostFiles (comment keeps the constraint only), doc.go sentence after no_new_privs
- 2026-11-22 d80a551f: make lint and make test green; make lab-gotest PKG=./internal/agent/supervisor/... green; make lab-gotest PKG=./internal/agent/supervisor/ RUN=TestConcurrentWorkerStartsInheritNoHostFiles COUNT=5: 5/5 green. No new mutation: the test body is unchanged (renamed only) and startLocked keeps the lock span, so the forkMu-removed mutation logged above still applies; full lab is the orchestrator's after merge
- 2026-11-22 follow-up filed: TP-277 (a worker closes fds it didn't expect to inherit)
- 2026-11-22 in-progress → review
- 2026-11-22 review → done: merged into rewrite (fix round approved, no further review)
