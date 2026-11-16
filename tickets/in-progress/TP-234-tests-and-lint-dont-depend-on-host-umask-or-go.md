---
id: TP-234
title: "Tests and lint don't depend on the host's umask or default Go"
milestone: M2
area: build
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-234"
branch: "tp-234-env-independent-tests"
---

## Goal
On a Linux host whose account umask is 0002 (common with per-user groups), some tests fail: directories they create come out group-writable and the code correctly refuses them. On a host whose default Go is newer than the repo's pinned toolchain, `make lint`'s vulnerability check fails on the newer standard library. Agents currently work around both per command (`umask 022`, `GOTOOLCHAIN=…`). Make the repo independent of both.

## Scope
- Tests that create files or directories the code checks for permissions set the modes they need explicitly (or the shared test helper does), instead of relying on the umask.
- The Makefile pins the toolchain go.mod names for every target (e.g. exporting GOTOOLCHAIN from go.mod's toolchain line), so `make lint` and `make test` use it whatever the host's default Go is.

## Out of scope

## Acceptance
- [ ] `make test` passes under `umask 0002` on Linux; the tests that failed under it are named in Notes with the fix.
- [ ] `make lint` and `make test` pass on a host whose default Go is newer than the pinned toolchain, with no GOTOOLCHAIN set by the caller.
- [ ] The product's permission checks are unchanged (tests, not the code, adapt); mutation-checked where a test changed.

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 backlog → in-progress, owner: agent-tp-234
