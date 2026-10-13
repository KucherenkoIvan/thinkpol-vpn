---
id: KRN-004
title: "app: second signal kills, injectable logger"
milestone: M1
area: app
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
owner: "agent-krn"
branch: "krn-004-app-second-signal-logger"
---

## Goal
A second Ctrl-C or SIGTERM kills a service whose shutdown hangs, and `app.Run` can log through an injected `*slog.Logger` instead of only `slog.Default()`. Motivation: a daemon like thinkpol's agent can hang in a `Close` phase (tunnel teardown, route restore), and today the operator has no way out except `kill -9`.

## Scope
- `app.Run` registers `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)` for its whole lifetime, including the Close phase, so every signal after the first is swallowed. Fix: after the first signal cancels the context, call `stop()` so the default disposition returns and the next signal terminates the process: `context.AfterFunc(ctx, stop)`. The first signal still gives the normal graceful shutdown, and the close timeout still applies.
- Log a line when the first signal arrives ("shutting down; signal again to force quit") so the operator knows the second one is meaningful.
- Edge to decide and document: if shutdown starts from an adapter failure rather than a signal, the signal handler is still installed during Close, so the first Ctrl-C would be swallowed. Release the handler when the Run phase ends too, or document why not.
- An option to inject the logger. `Run(ctx, adapters ...Adapter)` can't take options without breaking callers, so keep it as is and add an options entry point (for example `RunWith(ctx, Options{Logger: l}, adapters...)`, `Run` delegating with the zero value). A nil logger means `slog.Default()` (today's behavior).
- Package README and `docs/guides/app.md` updated (docs completeness rule): the two-stage shutdown behavior, the logger option, an anti-patterns row if one fits.

## Out of scope
- Making the close timeout configurable.
- Signals other than SIGINT/SIGTERM, Windows console control events.
- Wiring a different logger into the other kernel packages.

## Acceptance
- [x] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [x] Test: a hung `Close`, first signal begins shutdown, second signal ends the process. Sending a real second SIGINT kills the test binary, so the test re-executes itself as a subprocess and asserts on its exit status
- [x] Test: with an injected logger the adapter started/stopped/closed lines go to it and not to `slog.Default()`
- [x] Package README and guide updated per go-kernel's docs completeness rule
- [x] Backward compatible: `Run` signature and clean-shutdown behavior unchanged
- [x] Minor tag released; tag recorded in Notes
- [x] thinkpol-vpn bumps `go.mod`; the agent's `app.Run` call in `cmd/thinkpol/up.go` (from TP-011) uses the injected logger and gets two-stage shutdown with no code change beyond the bump

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Pairs with KRN-005: the injected logger is how a daemon with its own log destination reaches `app`'s lines.
- **go-kernel branch** `krn-004-app-second-signal-logger` (from `master` at `cf4db30`): `2a6df03` feat(app): second signal force-quits, RunWith with an injected logger; `b1164d8` docs(app).
- **API added** (`Run` unchanged; it delegates with zero `Options`):
  - `type Options struct { Logger *slog.Logger }` (nil is `slog.Default()`, read when `RunWith` starts)
  - `RunWith(ctx context.Context, opts Options, adapters ...Adapter) error`
- **Behavior:** `signal.Notify` on a channel instead of `signal.NotifyContext`. The first SIGINT/SIGTERM calls `signal.Stop`, logs `shutting down; signal again to force quit` (with `signal=`), and cancels the run context; graceful shutdown and the 15s close budget are unchanged. The next signal gets the default action and kills the process.
- **Edge decision (shutdown not started by a signal):** the handler is released as soon as shutdown begins for any reason (`context.AfterFunc` on the errgroup context, plus a synchronous `signal.Stop` after the Run phase, before any `Close`). After an adapter failure or a parent-ctx cancellation, the **first** SIGINT/SIGTERM already force-quits: nothing is left for a signal to start gracefully, and swallowing it would remove the only way out of a hung `Close`. Documented in the guide, along with two consequences of using the default action: a program with its own `signal.Notify` for these signals gets later signals itself, and a process started with SIGINT ignored goes back to ignoring it (SIGTERM still works).
- **Tests:** `app/signal_test.go` (unix) re-executes the test binary as a subprocess: a hung `Close` with the second signal kills (SIGINT and SIGTERM, asserted through `WaitStatus.Signaled()`/`Signal()`); after an adapter failure the first SIGINT kills a hung `Close`; a single SIGINT exits 0 with the force-quit hint, `adapter stopped` and `adapter closed` logged through the injected logger. `app_test.go`: an injected logger gets started/stopped/closed and `slog.Default()` stays silent; a nil logger logs through `slog.Default()`. Mutation check: with the handler release removed, the kill tests fail (the helper hangs). `go test -race -count=20 ./app/` passes.
- **Adoption for thinkpol-vpn:** `go.mod` bump only; two-stage shutdown applies to the existing `app.Run` call. Injecting the logger means `app.RunWith(ctx, app.Options{Logger: logger}, adapters...)`.
- **Release plan:** one combined minor release **v0.19.0** for KRN-003, KRN-004 and KRN-005 (all three are additive API, none depends on another, and the consumer adopts them together). Tag after review passes and the three branches are merged into go-kernel `master`. The branches touch adjacent one-line summaries in go-kernel `README.md` (guide list) and `docs/guides/service-runtime.md` (package table), so the 2nd and 3rd merge each hit a trivial conflict: keep both sides, each branch changes only its own package's row. A trial merge of all three with that resolution passes `make lint` and `make test`.
- **Released as go-kernel `v0.19.0`** (annotated tag on master `8004999`, verified on proxy.golang.org), together with KRN-003/004/005. go-kernel master merges: `a1f41ab` (config), `47cc578` (app), `8004999` (observability); the adjacent README/service-runtime rows were resolved keeping every side, `make lint` + `make test` green after each merge.
- **Review:** passed with no findings.
- **Adopted** on `krn-adopt-v0.19.0` (`b4500c5`): `go.mod` → v0.19.0; `thinkpol up` runs `app.RunWith(ctx, app.Options{Logger: logs.Logger}, ...)`. `slog.SetDefault(logs.Logger)` stays because `nsthread` logs through the default logger. `cmd/thinkpol/main.go` already releases its own `NotifyContext` after the first signal, so on a signal both handlers let go and the second signal kills. After an adapter failure, main's handler still takes the first signal (it cancels and releases), and the second one kills.

## Log
- 2026-10-11 created in backlog
- 2026-10-13 backlog → in-progress — owner: agent-krn, branch: krn-004-app-second-signal-logger (go-kernel branch krn-004-app-second-signal-logger)
- 2026-10-13 in-progress → review — go-kernel branch krn-004-app-second-signal-logger pushed; release planned as v0.19.0 after review
- 2026-10-13 review → done — merged into rewrite with the v0.19.0 adoption (krn-adopt-v0.19.0); go-kernel tag v0.19.0
