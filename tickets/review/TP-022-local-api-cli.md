---
id: TP-022
title: "Local service API and CLI"
milestone: M1
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-011, KRN-001]
refs: [D8, DESIGN#desktop-client]
owner: "agent-tp-022"
branch: "tp-022-local-api"
---

## Goal
A running device node is controlled through a local API, and the CLI is its first client (the tray app is the second, in M5).

## Scope
- gRPC API on a root-owned Unix socket, group-accessible (`thinkpol` group): connect, disconnect, status (space, chain, entry, health), switch rule preset, list enrolled spaces.
- API schema in the `proto/` buf module (`make proto`); unary calls only (streaming status waits for KRN-002).
- CLI: `thinkpol connect | disconnect | status | rules preset <name>`.

## Acceptance
- [x] the CLI controls a running device node in the lab — `lab/localapi_test.go` `TestLocalAPI`: device-a runs `thinkpol up -connect=false`; a `thinkpol` group member runs `thinkpol status` (disconnected, no ping), `thinkpol connect` (pings to the server and, relayed, device-b), `thinkpol status` (health ok, peers with handshake, neighbors with the udp link up; `-json` too), `thinkpol disconnect` (the TUN is gone, no ping, device-b unaffected) and root connects again; server-1's status shows its worker and listeners and `thinkpol connect` there is refused; no status or JSON shows any node's keys or lab addresses; after the stop the socket is gone
- [x] a user outside the group gets permission denied — same test: a user with no groups and one with another group get "permission denied" from `status`, `connect`, `disconnect` and `logs` (the directory refuses them); a group member gets "permission denied: only root" from `logs`; the socket directory is `750 root thinkpol`, the socket `660 root thinkpol`. Unit tests check the per-call policy over a real socket by the test process's own credentials (`internal/agent/localapi`)

## Notes
- **From TP-011's review (deferred here):**
  - **Composition out of `internal/agent`.** `Node.Run` calls go-kernel `app.Run` itself today (`internal/agent/node.go`). Make the agent return its `[]app.Adapter` (map watcher, data plane or supervisor + spaces, and the local API server added here) and let `cmd/thinkpol/up.go` compose them with `app.Run`, so the API server is one more adapter and the agent package stops owning process lifecycle.
  - **A read-only status handle out of `RunDataPlane`.** The engine lives inside `RunDataPlane` (`runner.engine`, nil while the node is removed from its space or a restart is pending). Expose a `Report`/`Status` handle (e.g. `DataPlane` gets a hook or `RunDataPlane` a returned handle) that yields `dataplane.Status`, the map version, `removed`/retry state and the listeners' keys, safe to call from the API's goroutines. `DataPlane.StatusAttrs` (renamed in TP-011's review) only adds attributes to the debug status line; don't grow it into the API.
  - **Server mode:** the API needs the `*supervisor.Supervisor` (`Workers()`, `Listeners()`, `Output(space)`), which `runServer` keeps local; worker output is space-controlled bytes, so sanitize it when rendering (TP-009 note), and serve a guest space's output only to its own admin (DESIGN rule 6).
  - `Logs.Ring` (`agent.NewLogs`) is the agent's in-memory log for the API to serve.

- **What was built (TP-022):**
  - **API** `proto/thinkpol/localapi/v1` (`LocalService`): `GetStatus`, `WatchStatus` (server stream, every interval ≥ 250ms), `Connect`, `Disconnect`, `ListSpaces`, `SetRulePreset`, `TailLogs` (server stream, last N lines then follow). Status: mode, space id, map version, removed, connection (disconnected / connecting / connected / serving), retrying, health (ok / degraded / down + fixed-vocabulary problems), and for a device's running data plane MTU, IPv6 on/off and why, last Apply's failed step, peers (overlay addresses, first hop in use = the entry, last handshake, bytes), neighbors and links, egresses (one per WireGuard device: chains will show up here by name), skipped entries, listener count, drop counters; for a server its workers (ready, starts, ready since, restart due) and public listeners (transport and counters, **no address**). Ids are hex; nothing is a public address, key or secret. Expected refusals are go-kernel domain errors (`permission_denied`, `server_mode`, `not_running`, `rule_presets_unavailable`, `unknown_rule_preset`); a failed connect is `UNAVAILABLE` naming only its step, the detail goes to the node's log.
  - **Auth model** (DESIGN.md "Desktop client" updated): socket `/run/thinkpol-api/api.sock` (macOS `/var/run/thinkpol-api/`), not under `/run/thinkpol`, which netcfg's lock dir and the workers' RunDir already use with mode 0700. The service creates the directory 0750 root:`thinkpol` (0700 if the group doesn't exist; `-api-group`/`THINKPOL_API_GROUP` takes a name or a gid) and refuses an existing one that isn't exactly that; the socket gets 0660 with the group. Every call is checked again by peer credentials (transport credentials read `SO_PEERCRED` + `SO_PEERGROUPS` on Linux, `LOCAL_PEERCRED` on macOS; unary and stream interceptors): root and the service's uid = admin (everything), group members = control (status, watch, spaces, connect, disconnect, presets), anyone else nothing. `TailLogs` is admin only (debug lines may quote the map). No read-only tier for other users: they can't reach the socket.
  - **Agent** (TP-011 deferrals): `Node.Run` is gone; `Node.Adapters(reload)` returns the map watcher and the node, and `cmd/thinkpol/up.go` composes them with `localapi.Adapter` under `app.Run`. `Node.Status()` is safe from any goroutine: the runner publishes into a mutex-guarded report (engine pointer cleared before the engine closes, `Engine.Status` called under the report's lock), the server path publishes version/removed/retrying and hands over the supervisor (cleared before `Close`). Listener *keys* are not exposed (they hold public addresses): only a count. `Node.Connect/Disconnect` go to the device's runner loop (`down` state: follows maps, starts nothing); a failed start is a `*agent.StartError{Step}` and leaves the device disconnected; a device removed from its space keeps the request for when it is back. `thinkpol up -connect` (`THINKPOL_CONNECT`, default true) chooses whether a device starts connected; a failing first start at boot is still fatal, as before.
  - **Sanitizing**: `agent.Sanitize` (the worker-output sanitizer, exported); `localapi.Client` sanitizes every string field of every response (protoreflect walk, map keys too) and every error message before the renderers see them. Guest workers' output is not served at all (only the owner space's lines reach the node's ring, as before), so DESIGN rule 6 holds; `Supervisor.Output(space)` stays unused until guest admins have a channel of their own.
  - **CLI**: `thinkpol status [-json] [-watch]`, `connect`, `disconnect`, `logs [-n N] [-f]` (root), `spaces`, `rules preset <name>`; all take `-socket` (`THINKPOL_API_SOCKET`). `Dial` probes the socket first, so a missing service and a refused caller get plain messages.
- **For TP-015 (rule engine):** implement `localapi.RulePresets` (`SetPreset(ctx, name) error`, `localapi.ErrUnknownPreset` for an unknown name) and pass it as `Options.RulePresets` in `cmd/thinkpol/up.go`; until then `SetRulePreset` answers `rule_presets_unavailable`. Add the active preset to `agent.Status` and the proto (new field) when it exists.
- **For TP-019 (macOS):** `peercred_darwin.go` (`LOCAL_PEERCRED` via `unix.GetsockoptXucred`) is written and vetted but never ran on a Mac; the default socket is `/var/run/thinkpol-api/api.sock` (`/var/run` is a symlink: the directory itself is created and checked with Lstat, the parent may be one). The pure-Go group lookup reads `/etc/group` only and won't see Directory Services groups: pass the gid (`THINKPOL_API_GROUP=<gid>`).
- **For TP-046 (service install):** create the `thinkpol` group and add the installing user; run the service as root; don't use systemd's `RuntimeDirectory=` for `/run/thinkpol-api` unless it ends up exactly 0750 root:thinkpol (the service refuses anything else; simplest is to let the service create it). Connect-on-boot is `THINKPOL_CONNECT` / `-connect` (default true today; D5 wants the installed default off).
- **For TP-049 (tray):** use `localapi.Client` (sanitized results, explained errors, `errors.Is` with `localapi.ErrPermissionDenied` / `ErrNotRunning` / `ErrServerMode`); `WatchStatus` for live state; the user must be in the `thinkpol` group. Missing for the tray, each a new RPC or field (wire-compatible additions): space switching (D9: `ListSpaces` returns one space today), `owned by <space>` for the entry in use (needs the entry's owner space in the map, TP-040), kill switch (TP-048) and connect-on-boot (TP-046) toggles.
- **Later:** a server's per-space data plane status lives in its worker process; reporting it needs a worker → supervisor status message over ipc (with TP-041's telemetry, or when guest admins get status).

## Log
- 2026-10-10 created in backlog
- 2026-10-11 docs (TP-011 review): notes on the composition, a status handle and the supervisor for the local API
- 2026-10-12 backlog → in-progress — owner: agent-tp-022, branch: tp-022-local-api
- 2026-10-12 in-progress → review — local API, auth model and CLI done; make lint, make test, make test-race and make lab-test green
