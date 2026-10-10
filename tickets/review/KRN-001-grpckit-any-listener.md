---
id: KRN-001
title: "grpckit: serve on any listener"
milestone: M1
area: grpckit
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#desktop-client]
owner: agent-krn-001
branch: krn-001-grpckit-any-listener
---

## Goal
thinkpol's local service API runs gRPC over a Unix socket (a named pipe on Windows later), but `grpckit.Run` only takes a TCP address.

## Scope
- `grpckit.Serve(ctx, srv, net.Listener)`; `Run` becomes a wrapper around it.
- Confirm `grpckit.Connect` works with `unix://` targets; add a test either way.
- Package README and guide updated (go-kernel's docs completeness rule); minor version tag.

## Acceptance
- [x] go-kernel `make lint`, `make test`, `make integration` pass
- [ ] released tag recorded in Notes; thinkpol-vpn's `go.mod` bumped to it

## Notes
- go-kernel branch `krn-001-grpckit-any-listener` (cut from `origin/master`; go-kernel's default branch is `master`, not `main`), head `b3233bc`:
  - `f040f78 feat(grpckit): Serve on any net.Listener`: `func Serve(ctx context.Context, srv *grpc.Server, lis net.Listener) error`. `Run(ctx, srv, addr)` keeps its signature and is now `net.Listen("tcp", addr)` + `Serve`. Serve owns `lis` and closes it on return. A test serves over a real Unix socket and dials `unix://<path>` through `grpckit.Connect`, which already handled the `unix` scheme without changes. Package README, `docs/guides/grpc.md` (new "Any listener" section plus an anti-pattern row), `docs/guides/app.md` and the `Connect` doc comment are updated.
  - `b3233bc fix(grpckit): return Serve errors instead of waiting for ctx`: a pre-existing bug. When the listener failed while ctx was still live, `Run` blocked until ctx was cancelled and then returned nil. Serve now returns the error right away and stops the server. There is a regression test.
- Planned tag: **v0.17.0** (new API → minor bump; latest tag is v0.16.0 at go-kernel `master`). It isn't merged or tagged yet: review comes first, then the orchestrator authorizes the merge, the tag and the push.
- The second acceptance box is left open on purpose. The tag only exists after review. The `go.mod` bump in thinkpol-vpn waits for TP-001, which creates `go.mod`, and will be done at merge time.
- Host gotcha: on this Mac, `make test` / `make integration` fail to link the cgo-using test binaries (cache, kafka, outbox, postgres, via testcontainers). The CommandLineTools linker can't read the macOS 27 SDK `.tbd` files. This is unrelated to the change. With `CGO_ENABLED=0` everything passes: `make lint` 0 issues, `make test` 15/15 ok, `make integration` 15/15 ok (kafka takes about 600s). `go test -race ./grpckit/...` passes with cgo.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-krn-001, branch: krn-001-grpckit-any-listener
- 2026-10-10 in-progress → review — go-kernel branch krn-001-grpckit-any-listener @ b3233bc, planned tag v0.17.0; tag and go.mod bump pending merge
