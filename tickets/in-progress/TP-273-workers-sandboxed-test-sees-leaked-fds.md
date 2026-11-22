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
- [ ] The leaked descriptors and their cause, with file:line, in Notes.
- [ ] The cause fixed; the test's leak check unchanged or stricter.
- [ ] A test or a reproduction that fails without the fix (mutation named in the Log).
- [ ] 20 consecutive green targeted runs of the test on the final commit.

## Notes
- Seen: TP-265/266 full labs, 2026-11-19 (TP-266's Log, R1.7).

## Log
- 2026-11-22 created in backlog (final-lab small fixes)
- 2026-11-22 backlog → in-progress, owner: agent-tp-273
