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
owner: "agent-claude-tp139"
branch: "tp-139-api-overview"
---

## Goal
The owner sees the whole user-facing surface of thinkpol as it is today in one readable document, and gives feedback before more is built on it, so poor design is caught early, while it's cheap to change.

## Scope
1. An overview document at `docs/design/api-overview.md`, generated from the code, not from memory. It covers every surface in the inventory below:
   - for each CLI command: its purpose, its flags with defaults, an example invocation with its real output (from a lab run or a test, never the owner's machine), its exit codes, and its error messages;
   - for the local API: each call, who may call it (its access group and the permissions it needs), and the request and response shapes;
   - for config: every key, its default, and where it is documented;
   - for on-disk state: each file, its owner and mode, and who reads it.
   - a "planned" part: the commands, settings, outputs and on-disk files that TP-111, TP-141, TP-133 and TP-140 propose, taken from their scopes and marked as not built yet, so the owner's verdicts reach those tickets before they start.
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
- [x] the overview covers every surface in the inventory (checked against the code by a reviewer)
- [x] every example output comes from a lab run or a test, never the owner's machine
- [x] the consistency findings list exists in the overview
- [x] the planned part covers TP-111, TP-141, TP-133 and TP-140, and each "change" verdict on it is written into that ticket
- [x] the owner's session is recorded in Notes, with a verdict (keep, change, or drop) on each finding
- [x] follow-up tickets for the "change" verdicts are filed and named in the Log

## Notes
- The owner's session was held on 2026-11-07. Its verdicts are below, one line per finding, each "change" line naming its follow-up ticket; the decided conventions are in docs/design/api-overview.md "Verdicts (owner, 2026-11-07)" and docs/design/configuration.md.
- **The documents the session used:** docs/design/api-overview.md (summary, configuration, on-disk state, planned part, findings F1–F21 with suggested verdicts, ordered by cost after M2) and docs/design/api-overview-reference.md (the CLI and local API, command by command, with example output). The reference is a second file because one file came to 67 KB, past the design docs' 50 KB split rule (ORCHESTRATION.md "Design documents"). Both are indexed from DESIGN.md.
- Acceptance box 1: the reviewer's round 1 check found coverage complete; ticked once R1.1–R1.3 were fixed. Box 4's first half is done (the planned part covers all four tickets); its second half, the "change" verdicts written into those tickets, waits on the session. Boxes 5 and 6 belong to the session.
- Inventory correction: the connect record (`connect`, `agent.ConnectRecordFile`) is not in the state directory. It sits next to the host lock in `/run/thinkpol` (macOS `/private/var/db/thinkpol`), and only when connect-on-boot is set. The overview places it there (F14).
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 0): done before the M2 lanes start, so the CLI's shape is reviewed before the kill-switch toggle and the transport settings are added to it.
- **Verdicts.**
  - F1 nowhere to put a setting: change (owner, 2026-11-07). Three levels: the map; a root-owned node file (0600 in the 0700 state directory, operating settings only, read by `up`, flags > env > file > defaults, the map only narrows); device toggles through the local API, stored next to the node file, replacing `rules.local`. Flat `key = value` files, JSON only where nesting is needed. Linux drop-ins unsupported, reported by `diag`. → TP-166
  - F2 three ways to change a setting: change (owner, 2026-11-07). Member toggles go through the local API and are stored by the service; operator settings go to the node file. → TP-166
  - F3 two JSON dialects: change (owner, 2026-11-07). `status` local and fast, no network; `diag` checks over the network, redacted so it can be shared, with a status snapshot as one section; one JSON convention (snake_case, every field, `schema_version`), opt-in with `-json`. → TP-168
  - F4 exit codes: change (owner, 2026-11-07). BSD sysexits: 0, 1, 64, 66, 69, 75, 77, 78; anything short of the requested state is not 0. → TP-167
  - F5 enumerated spellings: change (owner, 2026-11-07). Machine codes and enumerated values snake_case; human text in words; what people type kebab-case. → TP-167
  - F6 command shapes: change (owner, 2026-11-07). `<setting> [value]` for every setting. → TP-167
  - F7 flag spelling: change (owner, 2026-11-07). Toggles `on|off`, booleans only for output switches; `-socket` everywhere (`up -api-socket` an alias); `-out` everywhere (`-o` an alias). → TP-167
  - F8 member settings need root: change (owner, 2026-11-07). Connect-on-boot becomes a member's toggle: the service always starts at boot and the stored toggle decides whether it connects. → TP-166
  - F9 "only root may do that" for any refusal: change (suggested verdict, owner did not object, 2026-11-07). → TP-167
  - F10 usage errors don't say why: change (suggested verdict, owner did not object, 2026-11-07). → TP-167
  - F11 help to stdout: change (suggested verdict, owner did not object, 2026-11-07). → TP-167
  - F12 only `status` has a machine form: change (suggested verdict, owner did not object, 2026-11-07); `-json` on every command that prints a status or a list ((owner, 2026-11-07)). → TP-167 (`-json`), TP-168 (the convention)
  - F13 CLI and API differ: keep, with one change (suggested verdict, owner did not object, 2026-11-07): `Connect` and `SetRulePreset` return the status together with the warning. → TP-167
  - F14 docs and code disagree: change (suggested verdict, owner did not object, 2026-11-07). Doc-only fixes done in this branch (DESIGN.md and AGENTS.md mark the tray and `admin serve` as planned; README links api-overview.md as the CLI reference); help texts → TP-167
  - F15 PRD S2 and the journal: keep (suggested verdict, owner did not object, 2026-11-07) (RR40); the S2 amendment's note is in TP-141's Notes.
  - F16 status rendering nits: change the first three (suggested verdict, owner did not object, 2026-11-07) → TP-167; the fourth is TP-140's.
  - F17 `service uninstall` with nothing installed: keep exit 0, change the group line (suggested verdict, owner did not object, 2026-11-07). → TP-167
  - F18 `worker` reads the whole config: keep (suggested verdict, owner did not object, 2026-11-07).
  - F19 `dev lists build -only` miscount: change (suggested verdict, owner did not object, 2026-11-07). → TP-167
  - F20 `rules.local` 0644: change (suggested verdict, owner did not object, 2026-11-07), write it 0600. → TP-167 (moot if TP-166 replaces it first)
  - F21 the planned surface repeats open choices: change (owner, 2026-11-07), settled by F1, F4, F5 and F7; the answers are written into TP-111, TP-141, TP-133 and TP-140 (and TP-048, TP-035, TP-049).
- **Security** (owner, 2026-11-07): keys stay as designed; node key rotation and revocation of a seized node (TP-169), and device keys in the OS keystore as a later should (TP-170), are documented now and built after the concept is proven; ephemeral nodes after the MVP. New row RR56. Node groups carrying settings: the orchestrator's proposal, not confirmed (docs/design/configuration.md, TP-035).
- **Also filed** from a code-quality pass on 2026-11-07: TP-172, TP-173, TP-174. After the MVP, to be decided: TP-171 (user-defined diag scripts).

## Review findings
Round 1 (fact-check against the code, 2026-10-28): coverage complete; F1's premise and F14's count are wrong; the rest are nits.
- [x] R1.1 F1 (api-overview.md summary, configuration, findings): only `service connect-on-boot` refuses an edited definition; `service install` warns and rewrites it (losing the edit, resetting connect-on-boot to off); `service uninstall` never compares, it just removes.
- [x] R1.2 F1: on Linux a systemd drop-in (`thinkpol.service.d/*.conf`) can add `Environment=` lines without breaking the exact-match check; nothing handles drop-ins and uninstall leaves them behind; the premise holds only for macOS (one plist). Same caveat in the reference's "nothing else configures the service".
- [x] R1.3 F14: "five env keys appear nowhere but their flag help" fits no counting; recount (by env name, and by flag) and state the method; `-api-group` is documented.
- [x] R1.4 Config table "Documented in" column: `-dns` is documented nowhere; the runbook never mentions `-map`; server-agent.md never mentions `-mode`; the service doc mentions only `-connect-on-boot`, not `-connect`.
- [x] R1.5 Reference: `not_running` is returned once the node has stopped, not before it starts (a call before start waits).
- [x] R1.6 Reference validation list: add `log level %q: want debug, info, warn or error`.
- [x] R1.7 Reference client errors: add `connecting to the local API at <path>: <err>`.
- [x] R1.8 Reference `service install` errors: add the no-systemd and no-/Library/LaunchDaemons errors.
- [x] R1.9 On-disk state: the server supervisor's cgroups `/sys/fs/cgroup/thinkpol/<space>` (0755) are missing.
- [x] R1.10 F9: "is refused every call" overstates the code; a member can be refused.
- [x] R1.11 Planned part, TP-111: add "owner lowering the ceiling is handled the same way".
- [x] R1.12 Planned part, TP-141: add "a start that finds the file wider than 0600 fixes it or refuses, and says so".

## Log
- 2026-10-23 created in backlog (owner: review the API's shape early, before more is built on it)
- 2026-10-24 docs: in the before-M2 list, ahead of the kill-switch and transport settings
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 0)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp139
- 2026-10-28 docs: docs/design/api-overview.md and api-overview-reference.md written from the code (CLI, local API, config, on-disk state, planned TP-111/141/133/140 surface, findings F1–F21); DESIGN.md indexes both
- 2026-10-28 examples captured from this branch in throwaway tests, not committed: `make lab-gotest PKG=./cmd/thinkpol` (help, usage, errors, dev commands in a lab node) and `go test -tags lab` (status, connect, disconnect, spaces, rules preset, logs, diag as root, alice and mallory against running nodes; service install, connect-on-boot and uninstall on a systemd node); nothing was run on the host
- 2026-10-28 doc-only change: no lab-tested code touched, so no `make lab-test` run; `make lint` and `make test` pass
- 2026-10-28 not verified: macOS output (paths and the launchd plist come from the code, not a run); Windows has no local API yet
- 2026-10-28 out of scope, for the orchestrator: F19 (`dev lists build -only` miscounts "others"), F20 (`rules.local` written 0644), F16 ("re-applied 1 times", the server's uplink line misaligned) are small code fixes if the owner says change; owner session pending
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.12)
- 2026-10-28 has-errors → in-progress — round 1 findings
- 2026-10-28 round 1 fixed, each item checked against the code: R1.1/R1.2 F1 rewritten (connect-on-boot refuses an edited definition, install warns and writes it over, uninstall removes it without comparing, `install.go:151,251-311`; Linux drop-ins pass the check but nothing handles them and uninstall leaves them; macOS has one plist), summary top-5, service files table, TP-111 row and reference unit/uninstall text updated; R1.3 F14 recounted with the method stated (9 of 14 by env name, 3 counting flags); R1.4 "Documented in" column fixed; R1.5–R1.8 reference gaps filled; R1.9 cgroups added (the leaf is `tp-space<slot>`, named after the worker's link, not `<space>` as the review said); R1.10 F9 narrowed to members added since login or past 16 groups; R1.11/R1.12 planned rows added
- 2026-10-28 doc-only round: no lab-tested code touched, no lab run; `make lint` and `make test` pass
- 2026-10-28 in-progress → review
- 2026-11-07 merged origin/rewrite
- 2026-11-07 docs: verdicts section in docs/design/api-overview.md; new docs/design/configuration.md, indexed from DESIGN.md; security.md records the key-management decision; new RESIDUAL-RISKS.md row RR56 (no existing row covered a seized node's keys staying valid until revoked by hand; RR52 covers what a seized device gives away); F14 doc fixes in DESIGN.md, AGENTS.md and README
- 2026-11-07 docs: TP-111, TP-141, TP-133, TP-140, TP-048, TP-035, TP-049 annotated; TP-111 and TP-048 depend on TP-166
- 2026-11-07 doc-only change: no code touched
- 2026-11-07 owner verdicts recorded; follow-ups filed: TP-166, TP-167, TP-168, TP-169, TP-170, TP-171, TP-172, TP-173, TP-174
