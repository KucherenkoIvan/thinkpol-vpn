---
id: TP-105
title: "go-kernel alignment drifts"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
owner: ""
branch: ""
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
- [ ] unit tests for config defaults and localapi error mapping updated or added as needed
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
