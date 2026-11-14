---
id: TP-211
title: "The lab and the tests run on a stock Linux Docker 29 host"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
`make test` and `make lab-test` pass on a stock Linux host with Docker 29 (AppArmor on, the account's umask 0002, a Go newer than go.mod's toolchain line), as they do on Docker Desktop 27, with nothing set up on the host and no overrides on the command line. Docker Desktop will move to 29 too, so the Mac's labs would break the same way.

## Scope
What a full lab and `make test` hit on such a host (measured 2026-11-14):
1. Docker 29's default seccomp profile denies `pivot_root` even with `CAP_SYS_ADMIN`: every server worker's sandbox (`internal/agent/supervisor/process_linux.go`, `internal/agent/worker/sandbox_linux.go`) dies with "sandbox: pivot_root: operation not permitted", and about 150 lab tests fail. Docker 27 allows it.
2. Docker's embedded resolver at 127.0.0.11 resolves outside names from inside the lab, so `TestSmoke/hermetic` fails ("Docker's resolver answered an outside name … want SERVFAIL").
3. Tests inherit the process umask: under umask 0002 the trusted-directory checks refuse the group-writable temp directories the tests create (264 tests fail).
4. `TestTheNodeFileIsStrictJSON` asserts a JSON error's position, which changed in Go 1.27: under `GOTOOLCHAIN=auto` a host's newer Go wins, since go.mod's toolchain line is a minimum.

## Out of scope
- Changing the host: everything is fixed in the repo.

## Acceptance
- [ ] The lab's nodes declare what they need, as they declare `apparmor=unconfined` in `lab/compose.go`: a seccomp setting that allows `pivot_root`, the narrowest that works, with the reason in a comment and `lab/README.md`.
- [ ] The hermetic DNS check holds on both Docker versions with no weaker oracle: the cause of the embedded resolver's answers is found and sealed in the lab's own setup; the test's tripwire is not loosened.
- [ ] Tests pass under umask 0002 and 0022: tests set the permissions they mean (explicit modes, Chmod) instead of inheriting the umask; the agent, under a root umask of 0002, doesn't create its own state or trusted directories group-writable and then refuse them (fixed here if it does and the fix is small, else named).
- [ ] `TestTheNodeFileIsStrictJSON` passes on Go 1.26.11 and 1.27.x: it asserts the error's meaning, not the stdlib's message text or position.
- [ ] A full `make lab-test` passes on a Linux Docker 29 host without umask or `GOTOOLCHAIN` overrides, and on Docker Desktop 27.

## Notes

## Log
- 2026-11-14 created (orchestrator's measurements on a Linux Docker 29 host)
