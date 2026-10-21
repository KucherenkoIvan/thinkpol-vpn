---
id: TP-116
title: "Go toolchain past GO-2026-6809"
milestone: M2
area: deps
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "orchestrator"
branch: "tp-116-go-toolchain-1-26-10"
---

## Goal
`make lint` passes again: govulncheck finds no reachable vulnerability in the standard library the build uses.

## Scope
- `go.mod`: `toolchain go1.26.9` → `go1.26.10`. govulncheck reports GO-2026-6809 (`crypto/x509`) as reachable with go1.26.9 (through `lab/prototypes/reality`); go1.26.10 fixes it. The `go` floor stays 1.26.0.

## Acceptance
- [x] `make lint` passes (govulncheck: 0 reachable vulnerabilities on every OS)
- [x] `make test` and `make lab-test` pass

## Notes
- Found by TP-112's implementer: `make lint` failed in vulncheck on a branch that didn't touch the code it flagged, so `rewrite` fails it too.

## Log
- 2026-10-21 created (TP-112's lint run)
- 2026-10-21 backlog → in-progress — owner: orchestrator, branch: tp-116-go-toolchain-1-26-10
- 2026-10-21 make lint green (govulncheck: 0 reachable on every OS), make test green, make lab-test green at 50ed43a (35 packages in the lab node)
- 2026-10-21 in-progress → review
