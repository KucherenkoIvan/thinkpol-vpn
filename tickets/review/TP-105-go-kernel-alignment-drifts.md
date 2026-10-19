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

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

The failed start's gRPC status code is now the interceptor's default `FailedPrecondition` (was a hand-built `Unavailable`): nothing in-repo branches on it, and the client's message is unchanged. `cmd/thinkpol/worker` still loads the config for its log level only, so it needed no default resolution.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-105-go-kernel-alignment-drifts
- 2026-10-19 implemented: platform defaults resolve in `up` after the load (config guide), `app.RunWith` gets a plain context so its two-stage shutdown owns SIGINT/SIGTERM, start failures go out as a domain error the interceptor encodes; DESIGN.md says grpckit has stream interceptors and says packet path, not data plane
- 2026-10-19 the shutdown works by lab evidence: `TestUpRunsTheM0Space` stops `thinkpol up` (supervisor and device) with SIGTERM and requires a clean exit with nothing left behind; the second-signal force-quit itself wasn't run anywhere
- 2026-10-19 in-progress → review — both acceptance boxes checked from this branch; nothing device-only to verify beyond the force-quit note above
