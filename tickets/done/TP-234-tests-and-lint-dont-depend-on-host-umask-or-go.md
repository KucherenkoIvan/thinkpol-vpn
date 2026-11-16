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
- [x] `make test` passes under `umask 0002` on Linux; the tests that failed under it are named in Notes with the fix.
- [x] `make lint` and `make test` pass on a host whose default Go is newer than the pinned toolchain, with no GOTOOLCHAIN set by the caller.
- [x] The product's permission checks are unchanged (tests, not the code, adapt); mutation-checked where a test changed.

## Notes
- **umask: no test fails under 0002 any more, so no test changes here.** The failures this ticket was filed for (every test using `t.TempDir()` with `internal/dataplane/trusteddir`: cmd/thinkpol, internal/agent, internal/agent/service, trusteddir; `t.TempDir()` is 0777 less the umask, so 0775 under 0002) were fixed by TP-211's `trusteddirtest.TempDir` (internal/dataplane/trusteddir/trusteddirtest/trusteddirtest.go:13, chmod 0755). At 14261c5, uncached `go test -count=1 ./...` on Linux under umask 0002 and under umask 0000 (group and world write both kept) is green: no other test relies on the umask. Plain `make test` there hid nothing either, but note it can show cached results from a run under another umask: the test cache isn't keyed on the umask.
- **Toolchain: the real failure was a tools/toolchain mismatch.** go.mod's `toolchain go1.26.11` is only a minimum under `GOTOOLCHAIN=auto`, so on a host with Go 1.27.4 `make` ran 1.27.4. Lint passed only while bin/tools had been built by that same Go; with tools built by go1.26.11 (a run with `GOTOOLCHAIN=go1.26.11` set by the caller) and a later run without it, govulncheck fails: `file requires newer Go version go1.27 (application built with go1.26)` on x/net's http2 files. The tools stamp didn't change with the toolchain, so nothing rebuilt them.
- **Fix:** the Makefile exports `GOTOOLCHAIN` from go.mod's toolchain line, or `go<version>` from the go line when Go has dropped the toolchain line (Makefile:3-17), and puts it in the tools stamp (Makefile:29), so every target (tests, lint, gofmt, tool installs, the lab's host-side `go`) runs the pinned toolchain, and changing the toolchain rebuilds the tools. `make GOTOOLCHAIN=...` on the command line still overrides it. README and tickets/ORCHESTRATION.md say so.
- The darwin tests weren't run under umask 0002; reading them, they create their trusted directories through `trusteddirtest.TempDir` too.
- No full lab: only the Makefile's toolchain handling and docs changed (the brief's rule); one `make lab-gotest` ran to show lab targets need no override either.

## Review findings
- [x] R1.1 (should-fix) Go drops the toolchain line when it equals the go line (`go mod tidy`, `go get go@X`); GOTOOLCHAIN was then exported empty, which Go treats as auto, and the stamp stopped following the toolchain. Fixed: fall back to `go<version>` from the go line, `$(error)` if go.mod has neither, and capture only `go[0-9.]+`, so a trailing comment or CRLF doesn't leak in (Makefile:3-17). Shown on temporary go.mod copies: toolchain line, no toolchain line (`go 1.26.11`), trailing comments, CRLF, CRLF without a toolchain line all export `go1.26.11` and key the stamp on it; a go.mod with neither line stops make; the old extraction gave an empty value without the line and a trailing CR with CRLF.
- [x] R1.2 (should-fix) lint's format check and `make fmt` ran the gofmt on PATH, the host's Go. Both now run `$(go env GOROOT)/bin/gofmt` from the pinned toolchain (Makefile:63-64, Makefile:98).
- [x] R1.3 (ticket) The Log's mutation `make vulncheck GOTOOLCHAIN=local` can't reproduce as written: the stamp name changes with it, so the tools rebuild with the local Go and pass. Redone with the go1.26.11-built tools' stamp renamed by hand to the local one (Log).
- [x] R1.4 (note) The darwin tests weren't run under umask 0002 (Notes).

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 backlog → in-progress, owner: agent-tp-234
- 2026-11-16 base origin/rewrite 5e2dc33. At 14261c5 on Linux (umask 0002, default Go 1.27.4, no GOTOOLCHAIN): `go test -count=1 ./...` green, and green again under umask 0000; make lint green at baseline only because the tools were built by the same Go
- 2026-11-16 Makefile exports GOTOOLCHAIN from go.mod's toolchain line and keys the tools stamp on it; README and ORCHESTRATION.md updated (465f777)
- 2026-11-16 at 465f777 on Linux (umask 0002, default Go 1.27.4, no GOTOOLCHAIN set by the caller): make lint green (tools reinstalled, govulncheck built by go1.26.11), make test green (39 packages, none cached), make's go reports go1.26.11; make lab-gotest PKG=./internal/dataplane/trusteddir/... green with no override
- 2026-11-16 mutation: the pin dropped while keeping go1.26.11-built tools fails govulncheck with "file requires newer Go version go1.27 (application built with go1.26)", the original failure; the pin restored, green
- 2026-11-16 mutation: trusteddirtest.TempDir's chmod 0755 removed, `go test ./internal/dataplane/trusteddir/... ./internal/agent/` under umask 0002 fails (TestLock, TestMakeMakesWhatIsMissingAndChecksIt, TestRecordsAreReadOnlyInTheirBoot and more); restored. No test changed on this branch; product permission checks untouched
- 2026-11-16 not verified: a host whose default Go is older than the pinned toolchain (the explicit GOTOOLCHAIN downloads it there too, as auto did); no full lab (Makefile toolchain handling only)
- 2026-11-16 in-progress → review
- 2026-11-16 review round 1: fix R1.1–R1.4, merge
- 2026-11-16 at 46ac1b6 on Linux (umask 0002, default Go 1.27.4, no GOTOOLCHAIN set by the caller): make lint green, make test green; on macOS (default Go 1.23.4) make lint green
- 2026-11-16 mutation redone for R1.3 at 46ac1b6: with the go1.26.11-built tools, their stamp renamed by hand to `.installed-local-…`, `make vulncheck GOTOOLCHAIN=local` fails govulncheck with "file requires newer Go version go1.27 (application built with go1.26)"; stamp renamed back, `make vulncheck` green
- 2026-11-16 review → done (merged)
