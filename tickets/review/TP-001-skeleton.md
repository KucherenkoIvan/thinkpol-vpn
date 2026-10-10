---
id: TP-001
title: "Clean slate and project skeleton"
milestone: M0
area: repo
repo: thinkpol-vpn
size: M
depends_on: []
refs: [DESIGN#repository-layout]
owner: agent-tp-001
branch: tp-001-skeleton
---

## Goal
The old prototype is gone and the repo has the layout, tooling and agent rules every later ticket builds on.

## Scope
- Remove the old code: `cmd/`, `internal/`, `pkg/`, `configs/`, `emulation/`, the committed `client` binary, the old Makefile. History keeps it at `01a8c23`.
- `go.mod`: `module github.com/KucherenkoIvan/thinkpol-vpn`, `go 1.25` (go-kernel's floor), go-kernel at its latest tag.
- Skeleton from DESIGN.md: `cmd/thinkpol` with only a `version` command; `internal/{agent,dataplane,netmap,features,shared}` with a `doc.go` each stating what belongs there.
- Makefile modelled on go-kernel's: `help`, `test`, `lint`, `fmt`, `tools`, and `lab-up` / `lab-test` / `lab-down` placeholders.
- `.golangci.yml`: go-kernel's standard set plus depguard rules: `internal/dataplane/**` and `internal/netmap/**` must not import `internal/features/**`, and `internal/features/**` must not import `internal/dataplane/**`.
- `AGENTS.md` (+ `CLAUDE.md` with `@AGENTS.md`): privacy (public repo: no employer or work references), PRD/DESIGN are the source of truth, the ticket workflow in `tickets/README.md`, "you are the CI" (`make lint` + `make test` before every commit), conventional commits, no cgo in `dataplane` and `netmap` (Android comes later), protobuf contracts stay in this repo and never go to go-kernel's `contracts/` (a thinkpol-only exception, see DESIGN.md "Kernel usage").
- README: short pitch, links to PRD, DESIGN and the board, dev setup (Go 1.25; go-kernel is public, so no `GOPRIVATE` or SSH setup is needed).
- `.gitignore`: `bin/`, `lab/bin/`, `*.test`, coverage files.

## Out of scope
Any functionality beyond `version`.

## Acceptance
- [x] `git ls-files` shows none of the old tree and no binaries
- [x] `make lint` and `make test` pass on the skeleton
- [x] `go run ./cmd/thinkpol version` prints a version
- [x] the depguard rule fails when a `dataplane` file imports a `features` package (checked once, not committed)

## Notes
Build everything with `CGO_ENABLED=0`.

- go-kernel is pinned at v0.16.0 by a blank import of its zero-dependency `ddd` package in `internal/shared/kernel.go`; without an import `go mod tidy` drops the require. Delete that file once real code imports the kernel.
- `cmd/thinkpol`: stdlib only, no CLI framework. Each subcommand is one file that calls `register` from `init`; commands get a context cancelled on SIGINT/SIGTERM and return `errUsage` for bad arguments (exit 2). `version` prints `thinkpol <version> <go> <os>/<arch>`: the version comes from `-ldflags -X main.version` (`make build` uses `git describe`), else the VCS stamp of `go build`, else `dev` (`go run` and tests).
- The Makefile exports `CGO_ENABLED=0` for every target and adds a `build` target. `lab-*` placeholders exit 1 so nothing mistakes them for a passing lab.
- `make lint` runs golangci-lint with `--allow-serial-runners`: agents in parallel worktrees share golangci-lint's lock, and without the flag a second run fails with "parallel golangci-lint is running" instead of waiting.
- depguard deny entries are prefix matches, so they cover every subpackage, and `**/internal/dataplane/**` also matches files directly in `internal/dataplane/`. Checked once by importing `features` from `dataplane`, `features` from `netmap` and `dataplane` from `features`: all three fail lint.
- No-cgo in `dataplane`/`netmap` is a rule in AGENTS.md and enforced only by building with `CGO_ENABLED=0`, not by a linter.
- Rebased onto `rewrite` at 59dd3a6 (board-ops commits). The `.gitignore` conflict was resolved in favour of the new, shorter file, which already ignores `__pycache__/`.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-001, branch: tp-001-skeleton
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
