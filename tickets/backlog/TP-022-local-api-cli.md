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

- **From TP-015's review (the local rules file):** a device's rule choice is `rules.Local` (`internal/dataplane/rules`) in its text form (`MarshalText`/`UnmarshalText`: an optional `preset <space|everything|all-but-domestic>` line, then one `match -> action` rule per line). The file is owned by the service, in its state dir, and written only through the privileged API (`rules preset <name>` and any rule edits go through it, never a user-writable file). The service hands it to the engine with `EngineConfig.Rules` at start and `Engine.SetRules` on change (persist, then apply). On a parse error keep the last good `Local` or fail closed; never run with a zero `Local`, which silently means "the space's rules". `SetRules` returns `rules.ErrPresetUnavailable` when the map can't build the preset (it is then enforced failing closed): say so in the CLI. `Status.Rules` gives the preset, whether it is unavailable, direct prefix counts and skipped rules by origin, index and reason only.

## Log
- 2026-10-10 created in backlog
- 2026-10-11 docs (TP-011 review): notes on the composition, a status handle and the supervisor for the local API
- 2026-10-12 docs (TP-015 review): notes on the local rules file
