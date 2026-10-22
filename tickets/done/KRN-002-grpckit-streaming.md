---
id: KRN-002
title: "grpckit: streaming interceptors"
milestone: M4
area: grpckit
repo: go-kernel
size: M
depends_on: []
refs: [docs/design/control-plane.md#control-plane-the-controller-on-go-kernel]
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
- [x] released tag recorded in Notes

## Notes
- go-kernel branch `krn-002-grpckit-streaming` (cut from `origin/master` @ `e53e68f` = v0.17.0), head `4cd0d74`, pushed; not merged, not tagged (review first):
  - `a348cbf feat(contracts): streaming RPCs on the example EchoService`: `EchoStream` (server streaming) and `EchoChat` (bidi) added to `grpc.example.v1.EchoService`, regenerated with the committed tool versions (protoc-gen-go v1.36.11, protoc-gen-go-grpc 1.6.2); `buf lint` and `buf breaking` pass. The tests run real streaming RPCs over this contract instead of grpc's interop services.
  - `026718e feat(grpckit): standard chain for streaming RPCs`: `NewServer` installs a stream server interceptor with the unary chain's guarantees (request id in `stream.Context()`, panic recovery, error logging, domain errors encoded into the status that ends the stream, the rest masked as `Internal`). New option `func WithStreamInterceptor(i grpc.StreamServerInterceptor) ServerOption`, mirroring `WithUnaryInterceptor` (appended inside the standard chain). `Connect` installs a stream client interceptor: request id sent with the stream, the final status decoded into `*RemoteDomainError` on `RecvMsg`/`SendMsg` (io.EOF untouched). grpckittest needs no change (it goes through `Connect`).
  - Behavior change, unary too (flag for review): an RPC ended by its own context (client cancel, deadline, or the connection closed by shutdown, where `Send` returns `Unavailable "transport is closing"`) is logged at debug and reported as `Canceled`/`DeadlineExceeded`, instead of an ERROR "handler error" masked as `Internal`. Without it every stream disconnect and every shutdown with open streams logs an error. Mutation-checked: dropping the `Unavailable` case fails the shutdown test.
  - `4cd0d74 docs(grpckit): ...`: grpc guide gets a "Streaming RPCs" section (server/client shape, long-lived streams and shutdown, one sender per stream), an error-mapping row and four anti-patterns; the "Unary RPCs only" limitation is removed. Middleware guide gets a stream auth interceptor (wrapping the stream to replace `Context()`) and an anti-pattern for unary-only auth. Package README updated.
- Shutdown with a long-lived stream: graceful stop doesn't end open streams, so a push stream holds `Serve` for the full grace period (10s), then its connection is closed and `stream.Context()` cancelled. `TestServe_LongLivedStreamShutdownIsBounded` (Unix socket, 300ms bound): Serve returns nil after at least the grace period and within the bound + slack, the handler saw its ctx done before Serve returned, the client stream errors, nothing logged at ERROR. `TestServe_ShutdownAwareStreamEndsBeforeTheBound`: a handler that also watches the ctx given to Serve ends the stream cleanly (client gets io.EOF) and Serve returns well before a 5s bound. The guide recommends this pattern for the controller's push channel.
- Test evidence on `4cd0d74`: `make lint` 0 issues (with a private `GOLANGCI_LINT_CACHE`; the shared cache reported stale paths from the krn-001 worktree); `CGO_ENABLED=0 make test` all packages ok; `go test -race -count=5 ./grpckit/...` ok; `CGO_ENABLED=0 go test -count=30 ./grpckit/...` ok; `CGO_ENABLED=0 INTEGRATION=1 go test ./grpckit/...` ok (23 tests). Integration suite run package by package with `-p 1` (Docker VM disk had ~340 MB free; checked between packages, nothing pruned): grpckit, sqlite, cache, postgres, outbox, events, health, httpapi, app, kafka all ok, i.e. every package with tests. Free space dipped to 0 MB while the redpanda container was being reaped, back to 337 MB after; a single-invocation `make integration` was not run to avoid filling the shared disk.
- Planned tag: **v0.18.0** (new API: `WithStreamInterceptor`, streaming RPCs on the example contract), on go-kernel master after review, by fast-forward as for v0.17.0. Tag box stays open until then.

- Review fix pass (2026-10-10), go-kernel head `cf4db30`, added on top of `4cd0d74` (no history rewrite, no force-push):
  - `9999506 feat(grpckit): StreamWithContext and WithGRPCOptions` (findings 4, 5, 7): `func StreamWithContext(ctx context.Context, ss grpc.ServerStream) grpc.ServerStream`, used by the standard stream interceptor, the stream auth test and the middleware guide. `func WithGRPCOptions(opts ...grpc.ServerOption) ServerOption`, appended after the standard chain; its doc says interceptors go through WithUnary/WithStreamInterceptor, because a raw `grpc.UnaryInterceptor` there runs outside the chain (checked in grpc-go v1.82: `unaryInt` is prepended to the chain). Test: `MaxRecvMsgSize(16)` reaches the server (over-limit message → ResourceExhausted). One shared `recoverPanic` helper.
  - `d8dbc62 fix(grpckit): report RPCs ended by their own context as Canceled/DeadlineExceeded` (findings 1, 2, 3): Canceled → debug "rpc cancelled"; DeadlineExceeded → warn "rpc deadline exceeded"; Unavailable while ctx is done → warn with the original error, with the requested comment about folding. Option 2b was used for finding 2: a separate fix commit, with the history (v0.17.0 ERROR + Internal → 026718e debug → d8dbc62 levels) stated in its body and in the tag message. Table test `TestHandlerError_CodesAndLogLevels` (13 cases, client code + message + exactly one log record): includes the plain error after ctx end (ERROR, Internal), Canceled from elsewhere while ctx is live (ERROR, Internal), and a wrapped status passing through with the wrapping text. `TestEcho_DeadlineIsAWarningNotAHandlerError` is end to end. `TestEchoStream_ClientCancelIsNotAHandlerError` is now deterministic: the held handler returns ctx.Err() on the cancel path.
  - Finding: with a client-side deadline, the handler almost always sees Canceled, not DeadlineExceeded. A probe gave 20/20 Canceled over bufconn: the client's RST_STREAM beats the server's own timer. So the e2e deadline test imposes the deadline on the server side (an outer `grpc.UnaryInterceptor` via WithGRPCOptions, standing in for a slow link), and the client, which has no deadline of its own, receives the server's encoded DeadlineExceeded. The guide says this.
  - `cf4db30 docs(grpckit): ...` (finding 6): the error-mapping table follows the code's order (domain first; ctx-ended rule with levels and "Since v0.18.0 this applies to unary RPCs too"; status errors pass through unchanged, wrapped ones with the wrapping text, verified against grpc-go `status.FromError`; anything else Internal). Also covered: a keepalive example (server params + enforcement policy, client params), WithGRPCOptions for TLS (Limitations corrected: a later `WithTransportCredentials` overrides Connect's default, verified in grpc-go), panic recovery covering only the handler goroutine, and client-streaming `CloseAndRecv` decoding through the same RecvMsg path (stated, no client-streaming RPC in the example contract). Three new anti-patterns; README bullets consistent.
- Test evidence on `cf4db30`: `make lint` 0 issues; `CGO_ENABLED=0 make test` all ok; `go test -race -count=10 ./grpckit/...` ok; `CGO_ENABLED=0 go test -count=30 ./grpckit/...` ok; each of the three new commits passed lint and grpckit tests on its own. Integration per package (`CGO_ENABLED=0 INTEGRATION=1 go test -p 1`, Docker free space checked between packages, 292–295 MB, nothing pruned): grpckit, sqlite, cache, postgres, outbox, events, health, httpapi, app, kafka all ok. Commit bodies and diff scanned for private names: none.

- **Released: `v0.18.0`** (annotated tag object `01cab9c`, pointing at `cf4db30`), authorized by the orchestrator after review. go-kernel `master` was fast-forwarded from `e53e68f` to `cf4db30` (linear history, no merge commit). `GOPROXY=https://proxy.golang.org go list -m github.com/KucherenkoIvan/go-kernel@v0.18.0` resolves (origin hash `cf4db30`). The tag message lists the new API (WithStreamInterceptor, StreamWithContext, WithGRPCOptions, the stream chain), the behaviour change (ctx-ended RPCs: Canceled at debug, deadline/Unavailable at warn, client codes Canceled/DeadlineExceeded instead of Internal, history 026718e → d8dbc62) and the example `EchoServiceClient` interface change (hand-written fakes need the two new methods).
- `go.mod` bumped to go-kernel v0.18.0 after merging `origin/rewrite` (`3eff213`) into the ticket branch: `go get github.com/KucherenkoIvan/go-kernel@v0.18.0 && go mod tidy`. thinkpol-vpn `make lint` (0 issues, all OS targets, android build, no-cgo check) and `make test` pass.

## Review findings
Two reviewers, accepted by the orchestrator. Nothing blocking in the runtime code; one fix pass, then release v0.18.0. The unary behaviour change itself is accepted.
- [x] 1. Logging levels for ctx-ended RPCs: Canceled → debug; DeadlineExceeded → WARN "rpc deadline exceeded" with the original error; Unavailable while the RPC ctx is done → WARN with the original error (may be a real dependency outage racing the cancel). Comment that a downstream Unavailable racing the cancel is folded into the client-facing code because nobody is left to receive it.
- [x] 2. The unary behaviour change in its own `fix(grpckit): report RPCs ended by their own context as Canceled/DeadlineExceeded` commit (applies to unary and streaming; previously ERROR + Internal), or a separate fix commit with the history noted in the tag message; the tag message states the behaviour change.
- [x] 3. Tests: unary deadline (DeadlineExceeded to the client, warn not handler error); a plain error returned after ctx ends still logs ERROR and is masked Internal; make `TestEchoStream_ClientCancelIsNotAHandlerError` deterministic.
- [x] 4. Export `grpckit.StreamWithContext(ctx, ss) grpc.ServerStream`; use it in the interceptor, the middleware-auth guide and the test (no hand-written principalStream copies); README bullet.
- [x] 5. `grpckit.WithGRPCOptions(opts ...grpc.ServerOption) ServerOption` passthrough (appended after the standard chain; interceptors go through WithUnary/WithStreamInterceptor); test that a keepalive or MaxConcurrentStreams option reaches the server; keepalive example in the long-lived streams section; Limitations section fixed.
- [x] 6. Docs accuracy: grpc.md error-mapping intro/table matches the code exactly (domain error first; ctx-ended rule; other errors Internal; existing statuses pass through); ctx-ended paragraph moved to "Error mapping" with "Since v0.18.0 this applies to unary RPCs too"; README lines consistent; handlerError comment (unary or streaming); panic recovery covers only the handler goroutine; client-streaming covered by a test or stated to use the same RecvMsg path.
- [x] 7. Optional: share the recover block if it stays clean.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-krn-002, branch: krn-002-grpckit-streaming
- 2026-10-10 in-progress → review — go-kernel branch krn-002-grpckit-streaming @ 4cd0d74, planned tag v0.18.0; merge and tag pending review
- 2026-10-10 review → has-errors — 7 findings from two reviewers, see Review findings
- 2026-10-10 has-errors → in-progress — owner: agent-krn-002, fixing review findings
- 2026-10-10 in-progress → review — review findings 1–7 fixed, go-kernel head cf4db30; integration ok per package
- 2026-10-10 released go-kernel v0.18.0 (master fast-forwarded to cf4db30); go.mod bumped
- 2026-10-10 review → done — merged into rewrite
