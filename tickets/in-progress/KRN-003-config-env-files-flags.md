---
id: KRN-003
title: "config: optional env files and flag binding"
milestone: M1
area: config
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#kernel-usage]
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
- [ ] go-kernel `make lint` and `make test` pass (`make integration` is not relevant to this package)
- [ ] Tests: load without env files ignores a `.env` in the working directory; flag overrides env; env overrides default; unset flag leaves the env value; help text names the env var; deferred `Validate` sees flag values; duplicate flag names error out
- [ ] Package README and guide updated per go-kernel's docs completeness rule
- [ ] Backward compatible: `Load`/`MustLoad` signatures and behavior unchanged
- [ ] Minor tag released; tag recorded in Notes
- [ ] thinkpol-vpn bumps `go.mod` and adopts it in `internal/agent/config.go` and `cmd/thinkpol/up.go` (drops the `os.DevNull` workaround, the repeated flag names/defaults and the second `Check` call)

## Notes
- Branch from go-kernel's `master`.
- The go-kernel API stays generic: nothing in it, its docs or its commit messages names thinkpol.
- Adoption depends on TP-011 being merged into `rewrite`; if this ticket is released first, the adoption checkbox moves with TP-011's follow-up.

## Log
- 2026-10-11 created in backlog
