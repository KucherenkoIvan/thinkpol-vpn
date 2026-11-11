---
id: TP-202
title: "Go toolchain past GO-2026-6859"
milestone: M2
area: deps
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-202"
branch: "tp-202-go-toolchain-1-26-11"
---

## Goal
`make lint` passes again: govulncheck finds no reachable vulnerability in the standard library the build uses.

## Scope
- `go.mod`: `toolchain go1.26.10` → `go1.26.11`, the lowest go1.26.x that fixes GO-2026-6859 (`net/http`), which govulncheck reports as reachable with go1.26.10. The `go` floor stays 1.26.0.

## Acceptance
- [ ] `make lint` passes (govulncheck: 0 reachable vulnerabilities on every OS)
- [ ] `make test` and `make lab-test` pass

## Notes
- Found by TP-026's implementer: `make lint` failed in govulncheck on a branch that didn't touch the code it flagged, so `rewrite` fails it too.

## Log
- 2026-11-12 created (TP-026's lint run)
- 2026-11-12 backlog → in-progress, owner: agent-tp-202
