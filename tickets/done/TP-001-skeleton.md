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

- **go-kernel** is pinned at v0.16.0 by a blank import of its zero-dependency `ddd` package in `internal/shared/kernel.go`; without an import `go mod tidy` drops the require. TP-034 deletes the file. It is the one exception to "no code in the `shared` root".
- **Commands** (`cmd/thinkpol/cli.go`): stdlib only, no CLI framework. `register(command{path, args, summary, hidden, run})` from `init` in the command's own file; `run(ctx, env, args)` gets `env{stdin, stdout, stderr}`. Dispatch takes the longest registered path among the leading words (a word stops at the first flag or argument containing whitespace). `register` panics if a path is a group prefix of another (a group prefix is never a command; this applies to hidden commands too). A bare group prefix lists its commands and exits 2 (`thinkpol dev -h` lists them on stdout, exit 0). `errUsage` prints the command's synopsis; `parseFlags` needs the FlagSet named after the command path, prints synopsis + flags on `-h` (exit 0) and after a bad flag (exit 2). `version` prints `thinkpol <version> <go> <os>/<arch>`: `-ldflags -X main.version` (`make build` uses `git describe`), else the VCS stamp of `go build`, else `dev`.
- **Lint** runs gofmt once, then `go vet` + golangci-lint for each of darwin, linux, windows (about 12 s warm), then `GOOS=android GOARCH=arm64 go build` over `dataplane`, `netmap` and `lists` minus `dataplane/{tun,egress,firewall}`, with the package list itself taken from `GOOS=android go list` (packages with only `_linux.go` files are included; packages with no Android files at all are left out; a failing or empty list fails lint), then `make nocgo`. Android counts as linux for build tags, so a `_linux.go` file is in the Android build too; desktop-only Linux code that must stay out of it needs `//go:build linux && !android`. Negative checks run once, not committed: a vet error in a `_windows.go` file fails only the windows pass; code that builds on darwin/linux/windows but not android fails the android build; a gofmt syntax error fails lint.
- **No cgo** is enforced by `make nocgo` (part of lint): `CGO_ENABLED=1 go list -deps` for darwin, linux, windows and android over `dataplane`, `netmap` and `lists` fails on any non-std package with cgo files (checked once with an `import "C"` file in `dataplane/wg`). `CGO_ENABLED=0` stays the Makefile default; `make test-race` turns cgo on. The earlier note here claimed the default alone enforced it, which was wrong: files importing "C" are silently skipped without cgo.
- **Tools** are pinned in the Makefile (golangci-lint v2.14.0, buf v1.73.0, protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2) and installed per checkout into `bin/tools`, not GOPATH/bin, so they don't clobber the go-kernel checkout's tools. `make lint`/`make proto` install them on first use: about 7 minutes cold in a fresh worktree (buf is the slow one), seconds once the Go build cache is warm. A version bump changes the stamp file name and reinstalls everything. golangci-lint runs with `--allow-serial-runners` so parallel worktrees wait for its lock instead of failing.
- **Proto**: `proto/buf.yaml` is the module (excluding `gen/`), `proto/buf.gen.yaml` generates into `proto/gen` with `go_package_prefix github.com/KucherenkoIvan/thinkpol-vpn/proto/gen`. `make proto` is a no-op until the first `.proto` exists (buf fails on an empty module). Checked once with a throwaway service schema: generated code builds and lints clean; TP-003 adds the first real schema and the protobuf/grpc requires.
- **Layout** decisions (DESIGN.md "Repository layout"): `internal/lists` is top-level, next to `netmap`, because the controller builds lists too and features may not import `dataplane`; distribution is `dataplane/blobs`. Service install (TP-046) is in `agent`; the kill switch (TP-048) in `dataplane/firewall`; macOS and Windows data planes (TP-019, TP-047) are per-OS files in the `dataplane` subpackages. `release` (TP-051) stays a non-code area.
- **depguard**, checked once with throwaway imports (one per rule, plus the per-feature example rule; `features/spaces` importing its own `spaces/domain` passed):
  - `internal/dataplane/router/probe.go: import '…/internal/features/members' is not allowed from list 'planes-without-control-plane': the node side must not import the control plane`
  - `internal/netmap/probe.go: import '…/internal/shared/probe' is not allowed from list 'planes-without-control-plane': shared is the control plane's; the node side must not import it`
  - `internal/agent/worker/probe.go: import '…/internal/shared/probe' is not allowed from list 'planes-without-control-plane': shared is the control plane's; the node side must not import it`
  - `internal/lists/probe.go: import 'github.com/KucherenkoIvan/go-kernel/ddd' is not allowed from list 'mobile-without-kernel': the data plane, the map and the lists stay free of go-kernel`
  - `internal/features/spaces/spaces.go: import '…/internal/dataplane/wg' is not allowed from list 'features-without-node-side': control plane features must not import the data plane`
  - `internal/features/members/members.go: import '…/internal/agent' is not allowed from list 'features-without-node-side': control plane features must not import the node agent`
  - `internal/shared/probe/probe.go: import '…/internal/features/members' is not allowed from list 'shared-without-features': shared code must not depend on a feature`
  - `internal/features/spaces/spaces.go: import '…/internal/features/members' is not allowed from list 'feature-spaces': features talk to each other only through shared/ports`
- Rebased once onto `rewrite` at 59dd3a6 before the first review; after that, no history rewrites.

## Review findings
Two reviewers (correctness, architecture); accepted by the orchestrator.

Blocking:
- [x] B1. Command registry supports groups: space-separated command paths, longest-prefix dispatch, per-command argument synopsis, `hidden` flag, group usage when only a prefix is given (exit 2), `errUsage` prints the command's own synopsis; a test registers `t a` and `t b` from two files; AGENTS.md says a group is just a shared prefix
- [x] B2. `make lint` covers every OS: gofmt (failing if gofmt itself errors), then `go vet` + golangci-lint for GOOS darwin, linux, windows, plus an `android/arm64` build of dataplane and netmap minus the desktop-only packages; AGENTS.md conventions for `_linux.go` files and lab-only tests (`THINKPOL_LAB`)

Should fix:
- [x] S1. Layout: DESIGN.md and the doc.go files give every ticket `area:` a home (dataplane subpackages, agent/supervisor and agent/worker, no code in the `shared` and `features` roots, admin panel handlers and page shell, GeoIP list tooling); tickets naming non-existent areas are fixed
- [x] S2. depguard: dataplane, netmap and agent never import features or shared; dataplane and netmap never import go-kernel; features never import dataplane or agent; shared never imports features; AGENTS.md: a new feature adds a rule denying other features; negative checks re-run and recorded in Notes
- [x] S3. Real no-cgo check (`make nocgo`, run by lint) over dataplane and netmap; `test-race` target; AGENTS.md rule scoped as in DESIGN (`cmd/thinkpol-tray` may use cgo); ticket Note no longer overstates enforcement
- [x] S4. Commands get an env {stdin, stdout, stderr}; `parseFlags` helper (FlagSet output to stderr, `-h` exits 0, parse errors are usage errors)
- [x] S5. AGENTS.md: cmd files are composition roots; features follow go-kernel's service structure (linked) with `ddd.DomainError`; the data plane is plain ports and adapters
- [x] S6. Protobuf home: `proto/` buf module, `proto/gen/` generated; DESIGN layout, AGENTS.md, `make proto`, pinned buf and protoc plugins in `make tools`, golangci exclusion; TP-003 and TP-022 don't invent `contracts/`
- [x] S7. Every tool pinned to an explicit version in the Makefile
- [x] S8. Privacy: no absolute local paths or host specs in AGENTS.md and tickets/ORCHESTRATION.md; worktrees at `../.worktrees/<repo>/<branch>`; AGENTS.md allows board ops and serial merges in the main checkout
- [x] S9. `.gitignore`: `/thinkpol`, `/thinkpol-tray`, `*.exe`; coverage narrowed to `/coverage.out` and `*.coverprofile`
- [x] S10. Second Ctrl-C falls through to the default; version test checks the prefix and trailing GOOS/GOARCH and covers the `dev` fallback; `slices.Sorted(maps.Keys(...))`; consistent write-error style; kernel.go names TP-034
- [x] S11. TP-002 Scope notes a `make lab` target (DESIGN and TP-024 refer to it)

Round 2 (delta review):
- [x] R2-1. AGENTS.md OS bullet: Android counts as linux for build tags; desktop-only Linux code needs `//go:build linux && !android`
- [x] R2-2. Makefile lists the mobile packages with `GOOS=android GOARCH=arm64 go list`, and an empty or failing list fails loudly
- [x] R2-3. `register` panics when a path is a group prefix of another path or the other way round; AGENTS.md says a group prefix is never itself a command
- [x] R2-4. `version` uses `parseFlags` (`-h` exits 0) and checks `NArg`
- [x] R2-5. `synopsis` panics on an unknown path

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-001, branch: tp-001-skeleton
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 2 blocking and 11 should-fix findings from review
- 2026-10-10 has-errors → in-progress — owner: agent-tp-001, branch: tp-001-skeleton
- 2026-10-10 docs win: fixed `area:` of TP-004, TP-019, TP-042, TP-043, TP-046, TP-047, TP-048, TP-049, TP-050 to match DESIGN.md's layout; TP-003 and TP-022 use `proto/`; TP-016 names `internal/lists`; TP-043 places the canvas island; TP-002 adds `make lab`; ORCHESTRATION.md loses host specs and absolute paths
- 2026-10-10 in-progress → review — every review finding checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 5 findings from the delta review (round 2)
- 2026-10-10 has-errors → in-progress — owner: agent-tp-001, branch: tp-001-skeleton
- 2026-10-10 in-progress → review — delta review findings checked; `make lint` and `make test` pass
- 2026-10-10 review → done — merged into rewrite
