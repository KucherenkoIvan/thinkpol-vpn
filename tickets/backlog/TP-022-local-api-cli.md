---
id: TP-022
title: "Local service API and CLI"
milestone: M1
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-011, KRN-001]
refs: [D8, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
A running device node is controlled through a local API, and the CLI is its first client (the tray app is the second, in M5).

## Scope
- gRPC API on a root-owned Unix socket, group-accessible (`thinkpol` group): connect, disconnect, status (space, chain, entry, health), switch rule preset, list enrolled spaces.
- API schema in the `proto/` buf module (`make proto`); unary calls only (streaming status waits for KRN-002).
- CLI: `thinkpol connect | disconnect | status | rules preset <name>`.

## Acceptance
- [ ] the CLI controls a running device node in the lab
- [ ] a user outside the group gets permission denied

## Notes
- **From TP-011's review (deferred here):**
  - **Composition out of `internal/agent`.** `Node.Run` calls go-kernel `app.Run` itself today (`internal/agent/node.go`). Make the agent return its `[]app.Adapter` (map watcher, data plane or supervisor + spaces, and the local API server added here) and let `cmd/thinkpol/up.go` compose them with `app.Run`, so the API server is one more adapter and the agent package stops owning process lifecycle.
  - **A read-only status handle out of `RunDataPlane`.** The engine lives inside `RunDataPlane` (`runner.engine`, nil while the node is removed from its space or a restart is pending). Expose a `Report`/`Status` handle (e.g. `DataPlane` gets a hook or `RunDataPlane` a returned handle) that yields `dataplane.Status`, the map version, `removed`/retry state and the listeners' keys, safe to call from the API's goroutines. `DataPlane.StatusAttrs` (renamed in TP-011's review) only adds attributes to the debug status line; don't grow it into the API.
  - **Server mode:** the API needs the `*supervisor.Supervisor` (`Workers()`, `Listeners()`, `Output(space)`), which `runServer` keeps local; worker output is space-controlled bytes, so sanitize it when rendering (TP-009 note), and serve a guest space's output only to its own admin (DESIGN rule 6).
  - `Logs.Ring` (`agent.NewLogs`) is the agent's in-memory log for the API to serve.

## Log
- 2026-10-10 created in backlog
- 2026-10-11 docs (TP-011 review): notes on the composition, a status handle and the supervisor for the local API
