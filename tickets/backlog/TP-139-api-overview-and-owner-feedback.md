---
id: TP-139
title: "API overview and an owner feedback session"
milestone: M2
area: cmd
repo: thinkpol-vpn
size: M
needs_human: decision
depends_on: []
refs: [S1, S2, docs/design/desktop-client.md#the-local-api]
owner: ""
branch: ""
---

## Goal
The owner sees the whole user-facing surface of thinkpol as it is today in one readable document, and gives feedback before more is built on it, so poor design is caught early, while it's cheap to change.

## Scope
1. An overview document at `docs/design/api-overview.md`, generated from the code, not from memory. It covers every surface in the inventory below:
   - for each CLI command: its purpose, its flags with defaults, an example invocation with its real output (from a lab run or a test, never the owner's machine), its exit codes, and its error messages;
   - for the local API: each call, who may call it (its access group and the permissions it needs), and the request and response shapes;
   - for config: every key, its default, and where it is documented;
   - for on-disk state: each file, its owner and mode, and who reads it.
2. A consistency pass, in the same document, as a findings list. Nothing is fixed here. The pass covers:
   - naming: verbs, flag spelling, singular and plural;
   - output formats: human versus machine-readable, and where JSON is available;
   - exit-code conventions;
   - error message style;
   - things the CLI and the local API do differently;
   - surfaces that exist in code but are not documented, and the reverse;
   - anything that contradicts PRD.md or DESIGN.md.
3. A feedback session with the owner. The orchestrator walks the owner through the document. The owner's verdict on each finding (keep, change, or drop) is recorded in `## Notes`. Each "change" becomes a new ticket, filed by the orchestrator.

**Surfaces to cover** (names only; paths are repo-relative; inventory taken at the `rewrite` branch, commit ef17e82):

- CLI commands, registered one per file in `cmd/thinkpol/` (dispatch in `cmd/thinkpol/cli.go`, entry point `cmd/thinkpol/main.go`):
  - `version`, `up`, `connect`, `disconnect`, `status`, `diag`, `logs`, `spaces`, `rules preset`, `service install`, `service uninstall`, `service connect-on-boot`, `dev keygen node`, `dev keygen space`, `dev map build`, `dev map rotate`, `dev map inspect`, `dev map spec`, `dev lists build`;
  - hidden, still a command: `worker` (`cmd/thinkpol/worker.go`);
  - the help forms (`help`, `-h`, `-help`, `--help`).
- Flags per command (defined in the command's file in `cmd/thinkpol/`):
  - `up`: state, map, mode, and the node config flags (below), via `config.BindFlags`;
  - `status`: socket, json, watch, interval;
  - `logs`: socket, n, f;
  - `diag`: socket, o;
  - `connect`, `disconnect`, `spaces`, `rules preset`: socket;
  - `service install`: connect-on-boot, user;
  - `service connect-on-boot`: positional `on` or `off`;
  - `worker`: space;
  - `dev keygen node`: out; `dev keygen space`: out, recovery-out;
  - `dev map build`: keys, out, version, insecure-secrets-seed; `dev map rotate`: keys, out; `dev map inspect`: keys, node-key;
  - `dev lists build`: format, only, out.
- Local API, the gRPC `LocalService` (`proto/thinkpol/localapi/v1/localapi.proto`; server in `internal/agent/localapi/`):
  - calls: GetStatus, WatchStatus, Connect, Disconnect, ListSpaces, SetRulePreset, TailLogs, Diagnose;
  - access per call: `methodAccess` in `internal/agent/localapi/auth.go`, with the peer checks in `internal/agent/localapi/peercred_*.go`;
  - socket and group: `internal/agent/localapi/listen_unix.go`, `group_darwin.go`, `group_other.go`.
- Config:
  - the node's config struct `Config` in `internal/agent/config.go`, with its env keys: THINKPOL_STATE_DIR, THINKPOL_MAP, THINKPOL_MODE, THINKPOL_LOG_LEVEL, THINKPOL_INTERFACE, THINKPOL_LINK_MTU, THINKPOL_MAP_POLL, THINKPOL_CONNECT, THINKPOL_CONNECT_ON_BOOT, THINKPOL_API_SOCKET, THINKPOL_API_GROUP, THINKPOL_DNS, THINKPOL_DNS_UPSTREAM, THINKPOL_EGRESS_ALLOWED;
  - the CLI's own env read: THINKPOL_API_SOCKET (`cmd/thinkpol/cli.go`);
  - lab tooling variables (THINKPOL_LAB*, THINKPOL_LAB_*): listed so the overview can say whether they are user-facing;
  - there is no node config file: configuration is environment plus flags. Input files that are read: the map spec YAML (`cmd/thinkpol/dev_map_*.go`, `internal/devmap/spec.go`) and the list sources for `dev lists build`.
- On-disk state:
  - state directory (`agent.DefaultStateDir`, `internal/agent/statedir_*.go`): `node.key` (`agent.NodeKeyFile`), `space.pub` (`agent.TrustFile`), `map.bin` (`agent.MapFileName`), `blobs/` with `index` (`internal/agent/blobstore.go`), `connect` (`agent.ConnectRecordFile`), `rules.local` (`agent.LocalRulesFile`);
  - local API socket directory: `api.sock` and `api.lock` (`internal/agent/localapi/listen_unix.go`);
  - lock and run directories: `internal/dataplane/netcfg/netcfg_linux.go`, `netcfg_darwin.go`, `internal/agent/hostlock_linux.go`, `internal/agent/worker/sandbox_linux.go`;
  - `forwarding.json` (`internal/agent/supervisor/forwarding.go`);
  - the service unit and launchd plist written by `service install` (`internal/agent/service/definition.go`, `install.go`);
  - the OS resolver configuration the node edits (`internal/dataplane/dns/resolvconf.go`, `system_*.go`);
  - key and map files written by the dev commands: `space.key`, `recovery.key`, `space.pub`, `<name>.key`, `<name>.pub`, `map.bin` (`internal/devmap/keys.go`, `cmd/thinkpol/dev_*.go`); `<name>.geoip` blobs (`internal/lists/buildfile.go`);
  - the `diag -o` output file (`cmd/thinkpol/diag.go`);
  - logs: in memory only (PRD S2); the overview confirms that nothing else is written.

## Out of scope
- Changing any API, flag, config key, file, or message in this ticket. Each change the owner asks for goes to its own follow-up ticket.
- Device-only behaviour: the overview documents what the code does. What a real Mac or Windows run shows belongs to the device checklist of the ticket that needs it.

## Acceptance
- [ ] the overview covers every surface in the inventory (checked against the code by a reviewer)
- [ ] every example output comes from a lab run or a test, never the owner's machine
- [ ] the consistency findings list exists in the overview
- [ ] the owner's session is recorded in Notes, with a verdict (keep, change, or drop) on each finding
- [ ] follow-up tickets for the "change" verdicts are filed and named in the Log

## Notes
- The owner's session has not been held yet. Verdicts go here, one line per finding: keep, change, or drop. Each "change" line names its follow-up ticket.
- **Order (owner, 2026-10-24).** In the before-M2 list: done before the M2 lanes start, so the CLI's shape is reviewed before the kill-switch toggle and the transport settings are added to it.

## Log
- 2026-10-23 created in backlog (owner: review the API's shape early, before more is built on it)
- 2026-10-24 docs: in the before-M2 list, ahead of the kill-switch and transport settings
