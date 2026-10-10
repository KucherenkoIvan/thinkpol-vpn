---
id: KRN-002
title: "grpckit: streaming interceptors"
milestone: M4
area: grpckit
repo: go-kernel
size: M
depends_on: []
refs: [DESIGN#control-plane-the-controller-on-go-kernel]
owner: "agent-krn-002"
branch: "krn-002-grpckit-streaming"
---

## Goal
grpckit's standard chain covers streaming RPCs, which the controller's push channel and the tray's live status need.

## Scope
- Server stream interceptor: panic recovery, request id, logging, domain-error encoding.
- Client stream interceptor: request-id propagation, domain-error decoding.
- `WithStreamInterceptor` option mirroring `WithUnaryInterceptor`.
- Tests; guide and README updated, removing the "Unary RPCs only" limitation; minor version tag.

## Acceptance
- [x] go-kernel `make lint`, `make test`, `make integration` pass
- [ ] released tag recorded in Notes

## Notes
- go-kernel branch `krn-002-grpckit-streaming` (cut from `origin/master` @ `e53e68f` = v0.17.0), head `4cd0d74`, pushed; not merged, not tagged (review first):
  - `a348cbf feat(contracts): streaming RPCs on the example EchoService`: `EchoStream` (server streaming) and `EchoChat` (bidi) added to `grpc.example.v1.EchoService`, regenerated with the committed tool versions (protoc-gen-go v1.36.11, protoc-gen-go-grpc 1.6.2); `buf lint` and `buf breaking` pass. The tests run real streaming RPCs over this contract instead of grpc's interop services.
  - `026718e feat(grpckit): standard chain for streaming RPCs`: `NewServer` installs a stream server interceptor with the unary chain's guarantees (request id in `stream.Context()`, panic recovery, error logging, domain errors encoded into the status that ends the stream, the rest masked as `Internal`). New option `func WithStreamInterceptor(i grpc.StreamServerInterceptor) ServerOption`, mirroring `WithUnaryInterceptor` (appended inside the standard chain). `Connect` installs a stream client interceptor: request id sent with the stream, the final status decoded into `*RemoteDomainError` on `RecvMsg`/`SendMsg` (io.EOF untouched). grpckittest needs no change (it goes through `Connect`).
  - Behavior change, unary too (flag for review): an RPC ended by its own context (client cancel, deadline, or the connection closed by shutdown, where `Send` returns `Unavailable "transport is closing"`) is logged at debug and reported as `Canceled`/`DeadlineExceeded`, instead of an ERROR "handler error" masked as `Internal`. Without it every stream disconnect and every shutdown with open streams logs an error. Mutation-checked: dropping the `Unavailable` case fails the shutdown test.
  - `4cd0d74 docs(grpckit): ...`: grpc guide gets a "Streaming RPCs" section (server/client shape, long-lived streams and shutdown, one sender per stream), an error-mapping row and four anti-patterns; the "Unary RPCs only" limitation is removed. Middleware guide gets a stream auth interceptor (wrapping the stream to replace `Context()`) and an anti-pattern for unary-only auth. Package README updated.
- Shutdown with a long-lived stream: graceful stop doesn't end open streams, so a push stream holds `Serve` for the full grace period (10s), then its connection is closed and `stream.Context()` cancelled. `TestServe_LongLivedStreamShutdownIsBounded` (Unix socket, 300ms bound): Serve returns nil after at least the grace period and within the bound + slack, the handler saw its ctx done before Serve returned, the client stream errors, nothing logged at ERROR. `TestServe_ShutdownAwareStreamEndsBeforeTheBound`: a handler that also watches the ctx given to Serve ends the stream cleanly (client gets io.EOF) and Serve returns well before a 5s bound. The guide recommends this pattern for the controller's push channel.
- Test evidence on `4cd0d74`: `make lint` 0 issues (with a private `GOLANGCI_LINT_CACHE`; the shared cache reported stale paths from the krn-001 worktree); `CGO_ENABLED=0 make test` all packages ok; `go test -race -count=5 ./grpckit/...` ok; `CGO_ENABLED=0 go test -count=30 ./grpckit/...` ok; `CGO_ENABLED=0 INTEGRATION=1 go test ./grpckit/...` ok (23 tests). Integration suite run package by package with `-p 1` (Docker VM disk had ~340 MB free; checked between packages, nothing pruned): grpckit, sqlite, cache, postgres, outbox, events, health, httpapi, app, kafka all ok, i.e. every package with tests. Free space dipped to 0 MB while the redpanda container was being reaped, back to 337 MB after; a single-invocation `make integration` was not run to avoid filling the shared disk.
- Planned tag: **v0.18.0** (new API: `WithStreamInterceptor`, streaming RPCs on the example contract), on go-kernel master after review, by fast-forward as for v0.17.0. Tag box stays open until then.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-krn-002, branch: krn-002-grpckit-streaming
- 2026-10-10 in-progress → review — go-kernel branch krn-002-grpckit-streaming @ 4cd0d74, planned tag v0.18.0; merge and tag pending review
