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
- go-kernel branch `krn-001-grpckit-any-listener` (cut from `origin/master`; go-kernel's default branch is `master`, not `main`), head `643a723` (review fixes on top of the first pass):
  - `f040f78 feat(grpckit): Serve on any net.Listener`: `func Serve(ctx context.Context, srv *grpc.Server, lis net.Listener) error`. `Run(ctx, srv, addr)` keeps its signature and is now `net.Listen("tcp", addr)` + `Serve`. Serve owns `lis` and closes it on return. A test serves over a real Unix socket and dials `unix://<path>` through `grpckit.Connect`, which already handled the `unix` scheme without changes. Package README, `docs/guides/grpc.md` (new "Any listener" section plus an anti-pattern row), `docs/guides/app.md` and the `Connect` doc comment are updated.
  - `b3233bc fix(grpckit): return Serve errors instead of waiting for ctx`: a pre-existing bug. When the listener failed while ctx was still live, `Run` blocked until ctx was cancelled and then returned nil. Serve now returns the error right away and stops the server. There is a regression test.
- Review fix pass (2026-10-10), on top of `b3233bc`:
  - `c3fbb40 fix(grpckit): bound graceful shutdown; Serve errors name the listener`: findings 1, 4, 5, 6. Package-level `shutdownTimeout` var (10s), then `srv.Stop()`. Serve returns nil only when ctx is cancelled; an external stop while ctx is live returns `ErrServerStopped`. Errors are wrapped as `grpckit: serve <addr>: %w`. The Serve doc comment says it owns both `lis` and `srv`. New tests: bounded stop (mutation-checked: it fails if the hard stop is removed), the listener is closed on failure and on a pre-cancelled ctx, the socket file is gone after return, the error text, and an external stop.
  - `643a723 docs(grpckit): Serve ownership, shutdown bound, unix socket recipe`: findings 2, 3, 7, 8, 9. The guide's `listenUnix` snippet was compiled and run in a scratch module: it reclaims a stale socket, refuses one with a live server, and sets the directory mode to 0750.
  - Finding 10: commit bodies were checked with `git log --format=%B` for private names; none found.
- Test evidence for `643a723`: `make lint` 0 issues; `CGO_ENABLED=0 make test` 15/15 ok; `go test -race -count=3 ./grpckit/...` ok. `CGO_ENABLED=0 make integration`: 13/15 ok, including grpckit. postgres and outbox fail in the full run because the postgres testcontainer dies in initdb with "No space left on device". The Docker VM disk has 401 MB free of 58 GB (99% used, shared with other stacks on this host). Run on their own, `CGO_ENABLED=0 INTEGRATION=1 go test ./postgres/ ./outbox/ -count=1` passes. A clean single `make integration` run needs Docker disk freed (owner's call, not pruned by the agent). The first pass (`b3233bc`) ran the full suite clean.
- Planned tag: **v0.17.0** (new API → minor bump; latest tag is v0.16.0 at go-kernel `master`). It isn't merged or tagged yet: review comes first, then the orchestrator authorizes the merge, the tag and the push.
- The second acceptance box is left open on purpose. The tag only exists after review. The `go.mod` bump in thinkpol-vpn waits for TP-001, which creates `go.mod`, and will be done at merge time.
- Host gotcha: on this Mac, `make test` / `make integration` fail to link the cgo-using test binaries (cache, kafka, outbox, postgres, via testcontainers). The CommandLineTools linker can't read the macOS 27 SDK `.tbd` files. This is unrelated to the change. With `CGO_ENABLED=0` everything passes: `make lint` 0 issues, `make test` 15/15 ok, `make integration` 15/15 ok (kafka takes about 600s). `go test -race ./grpckit/...` passes with cgo.

## Review findings
Two reviewers (adversarial; architecture/style), accepted by the orchestrator. Nothing blocking; one fix pass before merge and tag.
- [x] 1. Bounded shutdown: after ctx cancel, GracefulStop is capped by a package-level `shutdownTimeout` var (10s, same as httpapi), then `srv.Stop()`. Test: a handler that blocks; cancel; Serve returns within timeout + slack.
- [x] 2. Guide "Any listener": access control through a parent directory created 0700/0750, not chmod after Listen (racy). One sentence saying per-caller authorization belongs in an interceptor using peer credentials (SO_PEERCRED/LOCAL_PEERCRED). Examples close lis on every error path. `unix://` paths are absolute (or use `unix:` + path).
- [x] 3. Guide shows Serve composed inside an `app.Adapter` Run, with the listener opened inside Run. Stale socket: dial first and remove only if nothing answers. Drop the FileListener-unlink claim. Link it from docs/guides/app.md.
- [x] 4. Document that Serve owns both lis and srv: it stops srv on return, there is one server per Serve call, and a listener failure does a hard Stop.
- [x] 5. Return logic: if ctx.Err() != nil return nil, else return the error; an external stop while ctx is live is an error. Wrap returned errors as `grpckit: serve <addr>: %w`.
- [x] 6. Tests: the failing listener records Close and Serve must close it. A pre-cancelled ctx returns nil promptly and closes the listener. The unix test asserts the socket file is gone after return. The failure test checks the error text.
- [x] 7. README example must not ignore the net.Listen error.
- [x] 8. Guide line for named-pipe clients (no grpc scheme; `passthrough:///` + WithContextDialer with go-winio) and that AF_UNIX works on Windows 10 1803+; don't choose for the consumer.
- [x] 9. grpckittest.Serve doc comment: "unlike grpckit.Serve, returns immediately with a connected client".
- [x] 10. Check commit bodies for private names (go-kernel privacy rule) before committing.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-krn-001, branch: krn-001-grpckit-any-listener
- 2026-10-10 in-progress → review — go-kernel branch krn-001-grpckit-any-listener @ b3233bc, planned tag v0.17.0; tag and go.mod bump pending merge
- 2026-10-10 review → has-errors — 10 findings from two reviewers, see Review findings
- 2026-10-10 has-errors → in-progress — owner: agent-krn-001, fixing review findings
- 2026-10-10 in-progress → review — review findings 1–10 fixed, go-kernel head 643a723; full make integration blocked by Docker disk space (postgres/outbox pass on their own)
