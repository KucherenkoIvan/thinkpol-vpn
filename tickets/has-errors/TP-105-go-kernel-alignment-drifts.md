---
id: TP-105
title: "go-kernel alignment drifts"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-105-go-kernel-alignment-drifts"
---

## Goal
thinkpol matches go-kernel's documented config, app, and gRPC patterns where it already uses those packages, and DESIGN.md no longer states capabilities the pinned kernel version has.

## Scope
- Move per-OS default resolution out of `os.LookupEnv` in `internal/agent/config.go` (~108, ~134) into `cmd/thinkpol/up.go` after load, per the config guide.
- Stop installing a second signal handler in `cmd/thinkpol/main.go` (~18) for service commands that use `app.RunWith`; keep `signal.NotifyContext` for plain CLI commands only.
- Replace hand-built `status.Errorf` for start failures in `internal/agent/localapi/server.go` (~203) with a domain error the gRPC interceptor encodes.
- Update DESIGN.md (~252): grpckit has streaming interceptors in the pinned go-kernel version; localapi already uses them.
- Wording: DESIGN should say there is no DDD in the packet path, not "no DDD in the data plane" (agent still models persisted and lifecycle state).

## Out of scope
- Deleting `internal/shared/kernel.go` (TP-106).
- localapi counter/refusal table consolidation (TP-083).

## Acceptance
- [x] unit tests for config defaults and localapi error mapping updated or added as needed — `TestUpAppliesThePlatformDefaults` (cmd/thinkpol/up_test.go) shows each platform default, the kept set-empty socket, and the default config validating; `TestLoadConfig` (internal/agent/node_test.go) shrank because the per-OS defaults left the load; the localapi round-trip test keeps its step-shown/detail-hidden assertions unchanged and gained `errors.Is(err, ErrStartFailed)`
- [x] `make lint`, `make test`, `make lab-test` pass — at 9aaa83b: lint and test clean; full lab run (GOFLAGS=-p=4, LAB_P=1, 34 packages) all PASS

## Review findings
- [ ] R2.1 cmd/thinkpol/up.go: runUp uses the ctx it's given (main passes Background for service commands) and passes it to app.RunWith; drop the comment that describes main.go from inside up.go.
- [ ] R2.2 internal/agent/localapi/client.go ~213-215: the codes.Unavailable special case is dead (only the deleted status.Errorf sent it); remove it, transport errors go through the general status path.
- [ ] R2.3 internal/agent/localapi/errors.go: ErrStartFailed is not a refusal the server sends (it's what the client wraps); move it out from under "The refusals and the gRPC codes they go out with" with its own comment; one source for the "start_failed" string (the prefix derived from ErrStartFailed.Code); state "the step rides in the code, the detail stays in the log" once.
- [ ] R2.4 internal/agent/config.go: StateDir/APISocket field docs and LoadConfig's doc describe what this package does now (LoadConfig neither validates nor fills platform defaults; DefaultStateDir/DefaultAPISocket are the platform defaults) and don't describe callers.
- [ ] R2.5 cmd/thinkpol/up.go applyPlatformDefaults: one shape for both fields (os.LookupEnv for each; set → keep, unset → the default); no second env read through apiSocket() inside it.
- [ ] R2.6 AGENTS.md ~32: "The **packet path** (`dataplane`, `netmap`, `lists`) is plain ports and adapters, no DDD aggregates." — matching DESIGN's "no DDD in the packet path".
- [ ] R2.7 DESIGN.md ~253-255: "`grpckit` for the push channel to nodes, whose streaming RPCs go through grpckit's stream interceptors like the local API's WatchStatus and TailLogs already do"; the node agent's kernel packages list includes grpckit (the local API).
- [ ] R2.8 cli.go/main.go: rename the command flag `service` to what it controls (e.g. ownsSignals).
- [ ] R2.9 Tests: pin the failed-start status code (FailedPrecondition) in localapi_unix_test.go on the raw RPC error; up_test.go uses t.Setenv(k, "") + os.Unsetenv for every THINKPOL_ variable it depends on (a developer's exported env must not break it) and also covers an env-set THINKPOL_STATE_DIR being kept; node_test.go's API-socket check that now proves nothing is removed or made meaningful.
- [ ] R2.10 errors from a failed Connect: say in the Log that grpckit now logs a failed Connect at DEBUG (a domain error) while the node's own WARN "connecting failed" remains — and whether that is acceptable (AGENTS/DESIGN on logging).

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

The failed start's gRPC status code is now the interceptor's default `FailedPrecondition` (was a hand-built `Unavailable`): nothing in-repo branches on it, and the client's message is unchanged. `cmd/thinkpol/worker` still loads the config for its log level only, so it needed no default resolution.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-105-go-kernel-alignment-drifts
- 2026-10-19 implemented: platform defaults resolve in `up` after the load (config guide), `app.RunWith` gets a plain context so its two-stage shutdown owns SIGINT/SIGTERM, start failures go out as a domain error the interceptor encodes; DESIGN.md says grpckit has stream interceptors and says packet path, not data plane
- 2026-10-19 the shutdown works by lab evidence: `TestUpRunsTheM0Space` stops `thinkpol up` (supervisor and device) with SIGTERM and requires a clean exit with nothing left behind; the second-signal force-quit itself wasn't run anywhere
- 2026-10-19 in-progress → review — both acceptance boxes checked from this branch; nothing device-only to verify beyond the force-quit note above
- 2026-10-19 review → has-errors — round 2: two reviewers said merge, the design reviewer's ten findings (R2.1–R2.10) recorded below
