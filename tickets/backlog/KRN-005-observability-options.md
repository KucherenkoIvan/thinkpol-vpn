---
id: KRN-005
title: "observability: writer, level and format options"
milestone: M1
area: observability
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
---

## Goal
`observability` can build a logger that writes somewhere other than stdout, with the level and format chosen by the caller rather than only by unprefixed `LOG_LEVEL`/`LOG_FORMAT` environment variables. Motivation: thinkpol's node agent is a daemon with its own log destinations (stderr, plus an in-memory ring of recent lines composed with `io.MultiWriter`), and a privileged daemon shouldn't take its log level from whatever `LOG_LEVEL` happens to be in the environment. Today `NewLogger` is stdout-only and JSON by default.

## Scope
- `observability.Options{Writer io.Writer, Level slog.Leveler, Format string}` and a constructor taking it (for example `NewLoggerWith(service string, opts Options) *slog.Logger`; `NewLogger(service)` delegates with the zero value). The constructor name is the implementer's call.
- Zero-value fields keep today's behavior: `Writer` nil is stdout; `Level` nil is `LOG_LEVEL` from the environment (default info); `Format` empty is `LOG_FORMAT` (default json). A non-nil `Level` means the environment is not read for it, and a `slog.LevelVar` works for runtime changes.
- `Format` accepts `json` and `text` (case-insensitive); an unknown value is an error or a documented fallback, decided and tested.
- The `service` attribute stays on every line.
- Package README and `docs/guides/observability.md` updated (docs completeness rule): the options, an example composing `io.MultiWriter(os.Stderr, sink)`, a row in the anti-patterns table if one fits.

## Out of scope
- A ring buffer or any log sink in the kernel; the caller brings its own `io.Writer`.
- Metrics and tracing.
- Prefixed environment variables.

## Acceptance
- [ ] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [ ] Tests: custom writer receives lines; explicit level beats `LOG_LEVEL`; explicit format beats `LOG_FORMAT`; zero Options behaves exactly like `NewLogger` (env-driven, stdout); `service` attribute present
- [ ] Package README and guide updated per go-kernel's docs completeness rule
- [ ] Backward compatible: `NewLogger` signature and output unchanged
- [ ] Minor tag released; tag recorded in Notes
- [ ] thinkpol-vpn bumps `go.mod` and adopts it in `cmd/thinkpol/up.go` (agent logger writes to stderr and the in-memory ring from `internal/agent/logring` through `io.MultiWriter`), then DESIGN.md "Kernel usage" drops the "not observability yet" line

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Until this lands the agent uses go-kernel's `config` and `app` but not `observability`.

## Log
- 2026-10-11 created in backlog
