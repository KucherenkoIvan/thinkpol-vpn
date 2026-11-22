---
id: TP-277
title: "A worker closes file descriptors it didn't expect to inherit"
milestone: later
area: agent/supervisor
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Defence in depth for the worker sandbox. TP-273 found a worker inheriting another worker's id-map fd, because Go's syscall opens it without close-on-exec, and fixed it by serializing worker starts (forkMu). Any future non-CLOEXEC fd in the agent, or in a library it uses, would reach a sandbox the same way. When this is done, a worker closes every fd above its known ones early in its init, so nothing it didn't expect survives into the sandbox, and the tests that look for leaks check sockets and pipes too.

## Scope
- Early in the worker's init (package worker), close every fd above the known ones (stdio, ControlFD, DataFD): `close_range`, or a `/proc/self/fd` walk where it isn't available.
- Test helpers that open SOCK_RAW sockets without SOCK_CLOEXEC get it: internal/agent/supervisor/supervisor_linux_test.go (~329, ~429), internal/agent/supervisor/arp_linux_test.go (~86).
- The leak check (`procLeakedFiles` in supervisor_linux_test.go flags host file paths only) also checks sockets and pipes against the worker's expected fd set.

## Out of scope
- forkMu itself (TP-273): it stays, since a worker's own close can't undo an fd held between its clone and its init.

## Acceptance
- [ ] A worker started with an extra inherited fd (test-injected) no longer holds it once Ready; the test fails with the close removed (mutation in the Log).
- [ ] The SOCK_RAW test helpers open with SOCK_CLOEXEC.
- [ ] The leak check flags an unexpected socket or pipe in a worker; mutation in the Log.
- [ ] Package docs (worker, supervisor) say what a worker closes and why.
- [ ] `make lint`, `make test` green; the supervisor and worker packages green in the lab.

## Notes
- Follow-up from TP-273's review, 2026-11-22.

## Log
- 2026-11-22 created in backlog (TP-273 follow-up)
