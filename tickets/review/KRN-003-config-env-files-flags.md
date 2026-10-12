---
id: KRN-003
title: "config: optional env files and flag binding"
milestone: M1
area: config
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
owner: "agent-krn"
branch: "krn-003-config-env-files-flags"
---

## Goal
`config.Load[T]` can skip `.env` files without a workaround, and a config struct can be bound to a `flag.FlagSet` from the same tags that drive the environment, so flags override env without repeating names or defaults. Motivation: thinkpol's `thinkpol up` (`internal/agent/config.go`, `cmd/thinkpol/up.go`, from TP-011) hand-repeats every env name and default as a flag and calls its own `Check` twice (once after env, once after flags). Callers today pass `os.DevNull` as the env file to avoid reading `.env` in a daemon's working directory.

## Scope
- An option to load without `.env` files. `Load[T](envFiles ...string)` can't take options without breaking callers, so keep it as is and add an options-based entry point (for example `LoadWith[T](opts ...Option)` with `WithEnvFiles(paths ...string)` and `WithoutEnvFiles()`); `Load` and `MustLoad` become thin wrappers. The exact names are the implementer's call; the constraint is that existing call sites compile and behave identically.
- `config.BindFlags[T any](fs *flag.FlagSet, cfg *T) error`: registers one flag per field carrying a `flag:"name"` tag (nested sections included). The flag's default is the value already in `cfg` (so env and `default:` tags win over nothing, and flags win over env), and the help text names the env var, e.g. `listen address (env HTTP_ADDR)`. An optional `help:"..."` tag supplies the description. Supports the same field types as `env:` (string, bool, ints, float64, `time.Duration`, `[]string`).
- `Validate()` runs after binding: `Load` currently validates before any flag is parsed, so add a way to defer it (an option such as `DeferValidate()`, plus an exported `config.Validate(cfg)` or equivalent that the caller invokes after `fs.Parse`). Without the deferral, validation would see env-only values.
- Duplicate `flag:` names and unsupported field types are reported by `BindFlags` as an error, not a panic at parse time.
- Package README and `docs/guides/config.md` updated (docs completeness rule): new tags, new precedence line (**flags > OS env > `.env.local` > `.env`**), an anti-patterns row ("repeating env names as flag names by hand").

## Out of scope
- Subcommand trees, `pflag`/cobra integration, env-name prefixes, config files other than `.env`.
- Changing the precedence of OS env over `.env` files.

## Acceptance
- [x] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [x] Tests: load without env files ignores a `.env` in the working directory; flag overrides env; env overrides default; unset flag leaves the env value; help text names the env var; deferred `Validate` sees flag values; duplicate flag names error out
- [x] Package README and guide updated per go-kernel's docs completeness rule
- [x] Backward compatible: `Load`/`MustLoad` signatures and behavior unchanged
- [ ] Minor tag released; tag recorded in Notes
- [ ] thinkpol-vpn bumps `go.mod` and adopts it in `internal/agent/config.go` and `cmd/thinkpol/up.go` (drops the `os.DevNull` workaround, the repeated flag names/defaults and the second `Check` call)

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Adoption depends on TP-011 being merged into `rewrite`; if this ticket is released first, the adoption checkbox moves with TP-011's follow-up.
- **go-kernel branch** `krn-003-config-env-files-flags` (from `master` at `cf4db30`): `8d74a14` feat(config): LoadWith options, BindFlags and deferred Validate; `64b26b3` docs(config).
- **API added** (`Load`/`MustLoad` unchanged; they delegate to `LoadWith`):
  - `type Option func(*loadOptions)`; `WithEnvFiles(paths ...string) Option` (replaces the default list; no paths reads no file); `WithoutEnvFiles() Option`; `DeferValidate() Option`
  - `LoadWith[T any](opts ...Option) (*T, error)`, `MustLoadWith[T any](opts ...Option) *T`
  - `Validate[T any](cfg *T) error` runs the `Validate()` hook (no-op without one), with the same `config: validation:` wrapping as `Load`
  - `BindFlags[T any](fs *flag.FlagSet, cfg *T) error`: tags `flag:"name"`, `help:"..."`
- **Decisions:** a flag's default is the field's value at bind time (bind after loading); the usage line is `<help> (env NAME)`, or `env NAME` without `help`. Duplicate names, names already on the FlagSet, malformed names (empty, leading `-`, containing `=`), unsupported types and a non-struct/nil config come back as one joined error, and then no flag is registered. Bool flags take `-x`/`-x=false` and hide `(default false)` like `flag.Bool`. `[]string` flags replace the list. `required:` stays an environment check at load time, so a value that may come from env or a flag leaves `required` off and is checked in `Validate()` (documented). Named string types (e.g. `type Mode string`) bind fine. Side fix: named `[]string` types now load from env instead of panicking.
- **Tests** (`config/flags_test.go`): `WithoutEnvFiles` ignores `./.env` while `Load()`/`LoadWith()` still read it; flag overrides env (nested section too); env overrides default (it becomes the flag default); unset flag keeps the env value; all types; bad flag value is a parse error; help text names the env var; deferred `Validate` sees flag values; duplicate, unsupported, malformed and already-defined names all error out without registering anything.
- **Adoption sketch for thinkpol-vpn** (after the tag): `config.LoadWith[Config](config.WithoutEnvFiles(), config.DeferValidate())`, `flag:`/`help:` tags on `agent.Config`, `config.BindFlags(fs, cfg)`, then `Check` once after `fs.Parse` (as the config's `Validate()` or called directly).
- **Release plan:** one combined minor release **v0.19.0** for KRN-003, KRN-004 and KRN-005 (all three are additive API, none depends on another, and the consumer adopts them together). Tag after review passes and the three branches are merged into go-kernel `master`. The branches touch adjacent one-line summaries in go-kernel `README.md` (guide list) and `docs/guides/service-runtime.md` (package table), so the 2nd and 3rd merge each hit a trivial conflict: keep both sides, each branch changes only its own package's row. A trial merge of all three with that resolution passes `make lint` and `make test`.
- The "minor tag released" and adoption boxes stay open until after review: the tag is pushed after review (ORCHESTRATION.md decisions), and adoption is a thinkpol-vpn change that follows the tag.

## Log
- 2026-10-11 created in backlog
- 2026-10-13 backlog → in-progress — owner: agent-krn, branch: krn-003-config-env-files-flags (go-kernel branch krn-003-config-env-files-flags)
- 2026-10-13 in-progress → review — go-kernel branch krn-003-config-env-files-flags pushed; release planned as v0.19.0 after review
