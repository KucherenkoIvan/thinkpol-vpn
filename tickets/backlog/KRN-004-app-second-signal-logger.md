---
id: KRN-004
title: "app: second signal kills, injectable logger"
milestone: M1
area: app
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
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
- [ ] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [ ] Test: a hung `Close`, first signal begins shutdown, second signal ends the process. Sending a real second SIGINT kills the test binary, so the test re-executes itself as a subprocess and asserts on its exit status
- [ ] Test: with an injected logger the adapter started/stopped/closed lines go to it and not to `slog.Default()`
- [ ] Package README and guide updated per go-kernel's docs completeness rule
- [ ] Backward compatible: `Run` signature and clean-shutdown behavior unchanged
- [ ] Minor tag released; tag recorded in Notes
- [ ] thinkpol-vpn bumps `go.mod`; the agent's `app.Run` call in `cmd/thinkpol/up.go` (from TP-011) uses the injected logger and gets two-stage shutdown with no code change beyond the bump

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Pairs with KRN-005: the injected logger is how a daemon with its own log destination reaches `app`'s lines.

## Log
- 2026-10-11 created in backlog
