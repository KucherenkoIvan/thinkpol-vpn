---
id: KRN-006
title: "Bump grpc and x/net past published vulnerabilities"
milestone: M1
area: deps
repo: go-kernel
size: S
depends_on: []
refs: []
owner: "cursor-glm-krn006"
branch: "krn-006-grpc-xnet-bump"
---

## Goal
go-kernel (public library) still requires google.golang.org/grpc 1.82.0 and golang.org/x/net 0.57.0, which carry reachable HTTP/2 server vulnerabilities (govulncheck: GO-2026-6443, GO-2026-6348, GO-2026-6061, GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6603); thinkpol-vpn already moved to grpc 1.84.0 / x/net 0.61.0 in TP-061.

## Scope
- Bump google.golang.org/grpc to 1.84.0 and golang.org/x/net to 0.61.0 in go-kernel's go.mod.
- Decide whether go-kernel's `go` directive must move to 1.26 (x/net >= 0.60 needs Go 1.26) and record the decision in Notes.
- Add govulncheck to go-kernel's `make lint` like thinkpol did.
- Release a minor tag.

## Acceptance
- [x] govulncheck clean
- [x] go-kernel `make lint`, `make test`, `make integration` pass
- [x] tag recorded in Notes; thinkpol-vpn `go.mod` bumped to it

## Notes

### go-kernel branch and commit
- Branch: `krn-006-grpc-xnet-bump` (off `origin/master`), pushed.
- Commit: `7ac9d5b` — `fix(deps): bump grpc and x/net past published vulnerabilities`.
- Follow-ups on the branch: `28607cd` (docs: go floor and toolchain directive), `5f65c7f` (test(app): the first-signal log assertion raced the stderr copy goroutine and failed under `make integration` load).
- Merged into go-kernel `master` as `72648f1` (`--no-ff`), tagged `v0.20.0` (annotated), pushed. The module proxy serves `github.com/KucherenkoIvan/go-kernel@v0.20.0`.

### Dependency bumps
- `google.golang.org/grpc` 1.82.0 → 1.84.0 (GO-2026-6443, GO-2026-6348, GO-2026-6061).
- `golang.org/x/net` 0.53.0 → 0.61.0 (GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610, GO-2026-6603).
- govulncheck also flagged reachable issues in `github.com/moby/go-archive` (GO-2026-6253 → v0.3.0) and `github.com/quic-go/quic-go` (GO-2026-5676 → v0.59.1); both bumped.
- `go mod tidy` pulled minor updates to x/crypto, x/sys, x/text, x/sync, x/mod, otel, genproto, etc.

### govulncheck before / after
- Before (grpc 1.82.0, x/net 0.53.0, go 1.25.0): 61 reachable vulnerabilities across 5 modules + the standard library (3 in grpc, 6 in x/net, the rest in the go1.25 stdlib).
- After (grpc 1.84.0, x/net 0.61.0, toolchain go1.26.9): 0 reachable vulnerabilities. (1 unreached advisory remains in `golang.org/x/crypto` v0.58.0 — GO-2026-5932, no fix available — not reachable from kernel code.)

### Go directive decision
- The `go` directive moved from `1.25.0` to `1.26.0`: x/net v0.61.0 requires Go >= 1.26.0, so 1.26.0 is the floor the dependencies now impose — kept as low as the dependencies allow (AGENTS.md "go.mod floor" rule).
- A `toolchain go1.26.9` directive was added so the standard library govulncheck (and the build) uses has its security fixes; the floor itself is not raised above 1.26.0, since it is imposed on every consumer. Mirrors what thinkpol-vpn's go.mod already does.
- Documented in go-kernel README.md (Development section) and the commit body.

### make lint / make vulncheck
- Added a pinned `govulncheck v1.9.0` installed per checkout into `bin/tools` via a stamp file, a `vulncheck` make target, and wired `vulncheck` into `make lint`. `make tools` now also installs the pinned govulncheck.

### Test results (go-kernel, CGO_ENABLED=0)
- `make lint`: pass (gofmt, go vet, golangci-lint v2.14.0 built with go1.26.9, govulncheck clean).
- `make test`: pass (all packages).
- Integration, one package at a time (`INTEGRATION=1 go test ./<pkg>/...`): grpckit, health (grpc importers, bufconn), postgres, cache, kafka, outbox, sqlite — all pass.

- go-kernel `make integration` (full suite, Docker) passes on the branch and on `master`'s tree; `make test` passes on `master` after the merge.

### Tag
- `v0.20.0` on go-kernel `master` merge commit `72648f1` (minor bump: new `go`/`toolchain` directive, `vulncheck` make target, dependency security bumps).

### thinkpol-vpn
- `go.mod`: `github.com/KucherenkoIvan/go-kernel` v0.19.0 → v0.20.0. thinkpol's own versions were already `google.golang.org/grpc` v1.84.0 and `golang.org/x/net` v0.61.0 (from TP-061), so nothing else moved; `go` stays 1.26.0, `toolchain` go1.26.9. The go-kernel bump removes the stale grpc 1.82.0 / x/net 0.57.0 requirements from the module graph that consumers of v0.19.0 inherit.
- govulncheck (`make vulncheck`, darwin/linux/windows/android): 0 reachable vulnerabilities before and after (0 in code, 0 in imported packages, 1 unreached advisory in a required module).
- `make lint` and `make test` pass. `make lab-gotest PKG=./internal/agent/localapi/...` passes (the real gRPC server over the unix socket); the only skip is the peer-credential test, which needs a non-root caller.

## Log
- 2026-10-13 created in backlog
- 2026-10-13 backlog → in-progress — owner: cursor-glm-krn006, branch: krn-006-grpc-xnet-bump
- 2026-10-13 in-progress → review — go-kernel branch krn-006-grpc-xnet-bump pushed (commit 7ac9d5b); govulncheck clean; make lint/test/integration pass; tag v0.20.0 and thinkpol-vpn go.mod bump deferred to post-merge
- 2026-10-13 review — go-kernel merged to master (72648f1) and tagged v0.20.0; thinkpol-vpn go.mod bumped to it; govulncheck 0 reachable, lint/test/lab-gotest localapi green
- 2026-10-13 review → done — reviewed (Cursor Opus: MERGE), go-kernel v0.20.0 tagged, merged into rewrite
