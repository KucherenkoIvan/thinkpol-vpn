---
id: KRN-006
title: "Bump grpc and x/net past published vulnerabilities"
milestone: M1
area: deps
repo: go-kernel
size: S
depends_on: []
refs: []
owner: "cursor-glm-krn006"
branch: "krn-006-grpc-xnet-bump"
---

## Goal
go-kernel (public library) still requires google.golang.org/grpc 1.82.0 and golang.org/x/net 0.57.0, which carry reachable HTTP/2 server vulnerabilities (govulncheck: GO-2026-6443, GO-2026-6348, GO-2026-6061, GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6603); thinkpol-vpn already moved to grpc 1.84.0 / x/net 0.61.0 in TP-061.

## Scope
- Bump google.golang.org/grpc to 1.84.0 and golang.org/x/net to 0.61.0 in go-kernel's go.mod.
- Decide whether go-kernel's `go` directive must move to 1.26 (x/net >= 0.60 needs Go 1.26) and record the decision in Notes.
- Add govulncheck to go-kernel's `make lint` like thinkpol did.
- Release a minor tag.

## Acceptance
- [ ] govulncheck clean
- [ ] go-kernel `make lint`, `make test`, `make integration` pass
- [ ] tag recorded in Notes; thinkpol-vpn `go.mod` bumped to it

## Notes

## Log
- 2026-10-13 created in backlog
- 2026-10-13 backlog → in-progress — owner: cursor-glm-krn006, branch: krn-006-grpc-xnet-bump
