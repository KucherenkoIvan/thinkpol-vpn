---
id: KRN-001
title: "grpckit: serve on any listener"
milestone: M1
area: grpckit
repo: go-kernel
size: S
depends_on: []
refs: [DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
thinkpol's local service API runs gRPC over a Unix socket (a named pipe on Windows later), but `grpckit.Run` only takes a TCP address.

## Scope
- `grpckit.Serve(ctx, srv, net.Listener)`; `Run` becomes a wrapper around it.
- Confirm `grpckit.Connect` works with `unix://` targets; add a test either way.
- Package README and guide updated (go-kernel's docs completeness rule); minor version tag.

## Acceptance
- [ ] go-kernel `make lint`, `make test`, `make integration` pass
- [ ] released tag recorded in Notes; thinkpol-vpn's `go.mod` bumped to it

## Log
- 2026-10-10 created in backlog
