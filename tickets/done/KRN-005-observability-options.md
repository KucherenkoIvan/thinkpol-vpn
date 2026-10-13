---
id: KRN-005
title: "observability: writer, level and format options"
milestone: M1
area: observability
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
owner: "agent-krn"
branch: "krn-005-observability-options"
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
- [x] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [x] Tests: custom writer receives lines; explicit level beats `LOG_LEVEL`; explicit format beats `LOG_FORMAT`; zero Options behaves exactly like `NewLogger` (env-driven, stdout); `service` attribute present
- [x] Package README and guide updated per go-kernel's docs completeness rule
- [x] Backward compatible: `NewLogger` signature and output unchanged
- [x] Minor tag released; tag recorded in Notes
- [x] thinkpol-vpn bumps `go.mod` and adopts it in `cmd/thinkpol/up.go` (agent logger writes to stderr and the in-memory ring from `internal/agent/logring` through `io.MultiWriter`), then DESIGN.md "Kernel usage" drops the "not observability yet" line

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Until this lands the agent uses go-kernel's `config` and `app` but not `observability`.
- **go-kernel branch** `krn-005-observability-options` (from `master` at `cf4db30`): `4fb0526` feat(observability): NewLoggerWith with writer, level and format options; `c98a15d` docs(observability).
- **API added** (`NewLogger` unchanged; it delegates with zero `Options`):
  - `type Options struct { Writer io.Writer; Level slog.Leveler; Format string }`
  - `NewLoggerWith(service string, opts Options) (*slog.Logger, error)`
- **Decisions:** each zero field keeps `NewLogger`'s behavior (stdout, `LOG_LEVEL` default info, `LOG_FORMAT` default json). A non-nil `Level` means `LOG_LEVEL` is never read; a `*slog.LevelVar` changes the level at runtime. `Format` is `json`/`text`, case-insensitive. **An unknown explicit `Format` is an error** (hence the `error` return: it comes from the caller's config and should fail the start), while an unknown `LOG_FORMAT`/`LOG_LEVEL` in the environment keeps the old lenient fallback to json/info. The `service` attribute stays on every line.
- **Tests** (`observability/logging_test.go`, the package's first): writer through `io.MultiWriter` gets lines on both sides with `service`; explicit level beats `LOG_LEVEL` both ways; `LevelVar` changes at runtime; explicit format beats `LOG_FORMAT` both ways; unknown `Format` errors while unknown `LOG_FORMAT` falls back to json; zero `Options` writes the same JSON as `NewLogger` to stdout (captured through a pipe) and follows `LOG_LEVEL`/`LOG_FORMAT`.
- **Adoption for thinkpol-vpn:** `observability.NewLoggerWith("thinkpol", observability.Options{Writer: io.MultiWriter(os.Stderr, ring), Level: &levelVar, Format: "text"})`, with the level parsed from `THINKPOL_LOG_LEVEL` (`slog.Level` implements `UnmarshalText`).
- **Release plan:** one combined minor release **v0.19.0** for KRN-003, KRN-004 and KRN-005 (all three are additive API, none depends on another, and the consumer adopts them together). Tag after review passes and the three branches are merged into go-kernel `master`. The branches touch adjacent one-line summaries in go-kernel `README.md` (guide list) and `docs/guides/service-runtime.md` (package table), so the 2nd and 3rd merge each hit a trivial conflict: keep both sides, each branch changes only its own package's row. A trial merge of all three with that resolution passes `make lint` and `make test`.
- **Released as go-kernel `v0.19.0`** (annotated tag on master `8004999`, verified on proxy.golang.org), together with KRN-003/004/005. go-kernel master merges: `a1f41ab` (config), `47cc578` (app), `8004999` (observability); the adjacent README/service-runtime rows were resolved keeping every side, `make lint` + `make test` green after each merge.
- **Review:** passed with no findings.
- **Adopted** on `krn-adopt-v0.19.0` (`b4500c5`): `go.mod` → v0.19.0; `agent.NewLogs` builds the logger with `observability.NewLoggerWith("thinkpol", Options{Writer: io.MultiWriter(stderr, ring), Level: <node level>, Format: "text"})`, so `LOG_LEVEL` is never read. Every line now carries `service=thinkpol` right after `msg`, so the agent and lab log assertions that expected `msg="map applied" version=` now allow attributes in between (`.*`). DESIGN.md "Kernel usage" lists `observability` for the agent and drops the "not observability yet" line. `make lint`, `make test` and `make lab-gotest PKG="./internal/agent/... ./cmd/thinkpol/"` (THINKPOL_LAB_MAX_LABS=2, GOFLAGS=-p=4) pass: 7 packages, data-plane tests included.

## Log
- 2026-10-11 created in backlog
- 2026-10-13 backlog → in-progress — owner: agent-krn, branch: krn-005-observability-options (go-kernel branch krn-005-observability-options)
- 2026-10-13 in-progress → review — go-kernel branch krn-005-observability-options pushed; release planned as v0.19.0 after review
- 2026-10-13 review → done — merged into rewrite with the v0.19.0 adoption (krn-adopt-v0.19.0); go-kernel tag v0.19.0
