---
id: TP-286
title: "labctl tests fail on macOS"
milestone: later
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
`go test ./lab/labctl/` passes on a Mac, as it does on Linux, so `make test` there is green without excuses.

## Scope
- `TestGotestSkipAndTimes` and `TestGotestRunsNodelessPackagesOnTheHost` (lab/labctl/main_test.go) fail on a Mac at b7beec15. The test module sits in a temp dir under `/var/folders/…`, a path through the `/var` → `/private/var` symlink; the package's directory reaches `go test` as a relative path climbing out of the resolved one (`./../../../../../../../private/var/folders/…/T/TestGotestSkipAndTimes…/001/tagged`), which go then resolves to `/private/private/var/…`:
  ```
  stat /private/private/var/folders/…/T/TestGotestSkipAndTimes…/001/tagged: directory not found
  FAIL	./../../../../../../../private/var/folders/…/001/tagged [setup failed]
  --- FAIL: TestGotestSkipAndTimes (0.07s)
      main_test.go:199: with -skip: gotest: failed: example.net/skip/tagged
  stat /private/private/var/folders/…/T/TestGotestRunsNodelessPackagesOnTheHost…/002/host: directory not found
  --- FAIL: TestGotestRunsNodelessPackagesOnTheHost (0.01s)
      main_test.go:373: on the host: lab: go test on the host ended (exit status 1) without a result for example.net/hostrun/host
  ```
- Find whether the test (root not symlink-resolved, as lab's `writeModule` resolves it) or labctl (how it makes a package's directory relative to the root) is wrong, and fix that one; a symlinked checkout path is a case the real code may meet too.

## Out of scope
- Other darwin-only test failures.

## Acceptance
- [ ] `go test ./lab/labctl/` passes on a Mac and on Linux.
- [ ] Every new or changed test mutation-checked, mutations in the Log.

## Notes
- Found by TP-285's implementer (2026-11-22), reproduced on a Mac with `go test ./lab/labctl/` at b7beec15 (rewrite); Linux runs pass.

## Log
- 2026-11-22 created in backlog (from TP-285)
