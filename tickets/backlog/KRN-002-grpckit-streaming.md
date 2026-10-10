---
id: KRN-002
title: "grpckit: streaming interceptors"
milestone: M4
area: grpckit
repo: go-kernel
size: M
depends_on: []
refs: [DESIGN#control-plane-the-controller-on-go-kernel]
owner: ""
branch: ""
---

## Goal
grpckit's standard chain covers streaming RPCs, which the controller's push channel and the tray's live status need.

## Scope
- Server stream interceptor: panic recovery, request id, logging, domain-error encoding.
- Client stream interceptor: request-id propagation, domain-error decoding.
- `WithStreamInterceptor` option mirroring `WithUnaryInterceptor`.
- Tests; guide and README updated, removing the "Unary RPCs only" limitation; minor version tag.

## Acceptance
- [ ] go-kernel `make lint`, `make test`, `make integration` pass
- [ ] released tag recorded in Notes

## Log
- 2026-10-10 created in backlog
