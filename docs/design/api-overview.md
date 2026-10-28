# thinkpol-vpn — API overview

This is everything a person or a script sees of thinkpol today: the CLI, the local API, the configuration, and the files on disk. It also lists the surface that four pre-M2 tickets plan to add, and ends with a consistency review. It describes the `rewrite` branch as built (TP-139). The command-by-command CLI and local API reference is in a second file, [API overview: reference](api-overview-reference.md), to keep each design file under 50 KB. The entry point is [DESIGN.md](../../DESIGN.md). Where this file and the code disagree, the code wins: this is a snapshot for review, not a source of truth.

**Where the examples come from.** Every example output here and in the reference was captured on 2026-10-28 from this branch, in two ways. Commands that need no running node ran inside a lab node, through `run()` in a throwaway test (`make lab-gotest`). Commands that need one ran against `thinkpol up` in a lab topology (`go test -tags lab`): the M0 space, `device-a` started with `-connect=false`, `server-1` serving, and a systemd node for `service`. Neither capture test is committed. Users: `root`; `alice`, in the `thinkpol` group; `mallory`, in neither. Ids, versions and timings are random per run. The dev map uses `192.0.2.10` and `2001:db8::10` as the server's address. No output shown here names a lab address.

## Summary

**What exists.**

- **One binary, `thinkpol`, with 19 visible commands and one hidden one.** There are four groups:
  - the node: `up`;
  - local API clients: `status`, `connect`, `disconnect`, `spaces`, `rules preset`, `logs`, `diag`;
  - the service: `service install|uninstall|connect-on-boot`;
  - development tooling: `dev keygen|map|lists …`.
  
  Plus `version` and the hidden `worker`.
- **A gRPC local API, `LocalService`, with 8 calls,** over a Unix socket in a directory that only root and the `thinkpol` group can reach. The group may call everything except `TailLogs`. `Diagnose` gives the group its snapshot without the host parts.
- **Configuration is environment plus flags.** There are 14 `THINKPOL_*` keys, all on `up`, and no config file. The installed service sets exactly one of them, `THINKPOL_CONNECT_ON_BOOT`.
- **On-disk state:**
  - the state directory: `node.key`, `space.pub`, `map.bin`, `blobs/`, `rules.local`;
  - runtime locks and records under `/run/thinkpol` (macOS: `/private/var/db/thinkpol`);
  - the API's socket directory;
  - the service unit or plist;
  - the resolver configuration the node rewrites while it runs.
  
  No log files.

**Top 5 findings**, ordered by what they would cost to change once M2 builds on them (full list in [Consistency findings](#consistency-findings)):

1. **F1. Nowhere to put a setting.** There is no node config file. The service unit carries only connect-on-boot, and it refuses any hand edit. TP-111 assumes "the root-owned file from TP-046", which was never built. TP-048's kill-switch toggle and M2's transport settings need a home too. Suggested verdict: **change**, decide the config home before TP-111 and TP-048.
2. **F2. Three ways to change a setting.** They are flags or env on `up`, a root-only rewrite of the service definition (`service connect-on-boot`), and a local API call whose result the service stores (`rules preset`). The tray can only reach the third one. PRD D4 and D5 want tray toggles. Suggested verdict: **change**, so that member-facing toggles go through the local API.
3. **F3. Two JSON dialects.** `status -json` uses protojson defaults: lowerCamelCase, zero values left out, 64-bit numbers as strings, `CONNECTION_CONNECTED`, no schema version. `diag` is snake_case, has every field, and is versioned. Suggested verdict: **change** `status -json` to diag's form before the harness and the kill-switch tests parse it.
4. **F4. Exit codes say too little.** There are only 0, 1 and 2. A partial success exits 1: a rule preset that was stored but can't be built yet, and a connect that came up without DNS protection. "Not running" and "permission denied" are both 1. Suggested verdict: **change**, define codes for scripts.
5. **F5. Enumerated strings use four spellings.** Problems and error codes are snake_case (`no_link_up`). Presets and a route's owner are kebab-case (`all-but-domestic`, `route-table`). Skip items use spaces (`inbound link`). JSON enums are SCREAMING_CASE. TP-140, TP-141 and TP-111 each add codes. Suggested verdict: **change**, write the rule down now.

## Contents

| Section | What it covers |
|---|---|
| [CLI](api-overview-reference.md#cli) (reference file) | dispatch, help, exit codes, every command with flags, an example and its errors |
| [Local API](api-overview-reference.md#local-api) (reference file) | the socket, the two gates, every call with its access and its shapes, refusals |
| [Configuration](#configuration) | every key, its default and where it is documented; input files; lab variables |
| [On-disk state](#on-disk-state) | every file the node, the service and the dev tools write or read |
| [Planned, not built](#planned-not-built) | what TP-111, TP-141, TP-133 and TP-140 propose |
| [Consistency findings](#consistency-findings) | F1–F21 with suggested verdicts |

## Configuration

### Node keys

There is no node config file. `up` reads the environment (`agent.LoadConfig`, with no `.env` files) and its flags override it. The state directory and the socket take their defaults from the OS (`ApplyOSDefaults`), and a variable set to empty stays empty.

| Env key | Flag | Default | Documented in |
|---|---|---|---|
| `THINKPOL_STATE_DIR` | `-state` | `/var/lib/thinkpol`; macOS `/private/var/lib/thinkpol` | flag help; `agent` doc (as `-state`) |
| `THINKPOL_MAP` | `-map` | `<state>/map.bin` | flag help; runbook, `agent` doc (as `-map`) |
| `THINKPOL_MODE` | `-mode` | `auto` | flag help; `agent` doc, server-agent.md |
| `THINKPOL_LOG_LEVEL` | `-log-level` | `info` | flag help; `agent` doc |
| `THINKPOL_INTERFACE` | `-interface` | platform default | flag help only |
| `THINKPOL_LINK_MTU` | `-link-mtu` | `0` (1500) | flag help only |
| `THINKPOL_MAP_POLL` | `-map-poll` | `5s` | flag help; runbook, `agent` doc |
| `THINKPOL_CONNECT` | `-connect` | `true` | flag help; `agent`, `localapi`, `service` docs |
| `THINKPOL_CONNECT_ON_BOOT` | `-connect-on-boot` | empty (the service sets `on` or `off`) | flag help; `agent`, `service` docs |
| `THINKPOL_API_SOCKET` | `-api-socket` (`up`), `-socket` (clients) | see [Socket and gates](api-overview-reference.md#socket-and-gates) | flag help; `localapi` doc (as `-api-socket`) |
| `THINKPOL_API_GROUP` | `-api-group` | `thinkpol` | flag help; `localapi`, `service` docs (as `-api-group`) |
| `THINKPOL_DNS` | `-dns` | `true` | flag help; `localapi`, `dns` docs (as `-dns`) |
| `THINKPOL_DNS_UPSTREAM` | `-dns-upstream` | empty | flag help; `dns` doc (as `-dns-upstream`) |
| `THINKPOL_EGRESS_ALLOWED` | `-egress-allowed` | empty | flag help; `dns` doc, RESIDUAL-RISKS.md (as `-egress-allowed`) |

Other variables the binary reads:

- `THINKPOL_API_SOCKET`: also read by every local API client, as the `-socket` default (`cmd/thinkpol/cli.go`).
- `SUDO_USER`: `service install -user`'s default.
- `DBUS_SYSTEM_BUS_ADDRESS`: the DNS reader's bus on Linux.
- the spec's `${NAME}` values, read by `dev map build` and `dev map rotate`.

### Input files

| File | Read by | Format | Documented in |
|---|---|---|---|
| map spec (`spec.yaml`) | `dev map build`, `dev map rotate` | YAML | `thinkpol dev map spec` (`internal/devmap/reference.yaml`), `internal/devmap/spec.go` |
| GeoIP source | `dev lists build` | v2fly `geoip.dat` or DB-IP Lite CSV, optionally gzipped | the command's help; `internal/lists/doc.go` |
| list blobs (`<name>.geoip`) | `dev map build` (named in the spec's `lists`) | the blob format | `internal/lists/doc.go` |

### Lab variables

These are not user-facing. They are read by the lab tooling and by tests, never by a node in normal use.

| Variable | Read by | Effect |
|---|---|---|
| `THINKPOL_LAB` | tests | set in lab nodes; tests that need root or namespaces skip without it |
| `THINKPOL_LAB_PROJECT` | lab | replaces the checkout part of Compose project names |
| `THINKPOL_LAB_KEEP` | lab, Makefile | a failed test's lab stays up |
| `THINKPOL_LAB_MAX_LABS` | lab | lab slots at once (default 12) |
| `THINKPOL_LAB_SUBNET_POOL` | lab | IPv4 range for lab networks |
| `THINKPOL_LAB_PERF` | tests | performance gates run only with it |
| `THINKPOL_LAB_GOARCH` | lab | architecture to build for |

All of these are documented in lab/README.md "Environment", except `THINKPOL_LAB` itself, which is documented in AGENTS.md.

## On-disk state

Paths are for Linux, with macOS in parentheses where it differs. "Node" means `thinkpol up` running as root.

### State directory: `/var/lib/thinkpol` (`/private/var/lib/thinkpol`)

The operator creates it, or the dev runbook does. It must be owned by root or the node's user, writable by no one else, and never a symlink anywhere on the path (`internal/agent/state.go`). PRD S1 says it holds exactly what the node needs.

| File | Written by | Mode (lab) | Read by |
|---|---|---|---|
| directory | operator | 0700 root | node |
| `node.key` | operator (from `dev keygen node`) | 0600 root | node; refused if `space.key` or `recovery.key` sits beside it |
| `space.pub` | operator | 0644 root | node: every map is verified against it |
| `map.bin` | operator (`dev map build`/`rotate`, copied in) | 0644 root | node, polled every `-map-poll` and on SIGHUP |
| `blobs/` | node (a device: lists fetched from peers) | dir 0700, files 0600 | node (a server only reads its seeds) |
| `blobs/index` | node | 0600 | node, after a restart |
| `rules.local` | node, when the local API sets a preset | 0644 root | node at start; a file that can't be parsed stops the node |

### Runtime directory: `/run/thinkpol` (`/private/var/db/thinkpol`)

`/run` is a tmpfs on Linux. On macOS this directory survives a reboot, and each record carries its boot session.

| File | Written by | Mode (lab) | Read by |
|---|---|---|---|
| directory | node | 0700 root | — |
| `agent.lock` | node: one agent per host | 0600 root | node, `service install`, `service uninstall` |
| `connect` | node, only with connect-on-boot set: the boot's connect choice | 0600 | node at start |
| `netcfg/<dev>-<ino>.<owner>.lock` (Linux) | node: one configurator per owner and namespace | 0600 | node |
| `netcfg/` lock and route record per owner (macOS) | node | — | node; `diag` |
| `forwarding.json` | a server's supervisor, only when it turned forwarding on | 0600 | the next supervisor, after a crash |
| `pf-guard.token` (macOS only) | node: the guard's `pfctl -E` reference | — | node; `diag` |

A server's worker gets a private tmpfs mounted at `/run/thinkpol` inside its sandbox (`internal/agent/worker/sandbox_linux.go`). Its netcfg locks go there, and nothing of the host's `/run` is visible. `service uninstall` removes locks, boot records and sockets from this directory and from the socket directory, and lists anything else it leaves.

### Local API directory: `/run/thinkpol-api` (`/private/var/db/thinkpol-api`)

`api.sock` (0660 root:`thinkpol`) and `api.lock` (0600 root) are written by the node. The directory is 0750 root:`thinkpol`. Clients connect to the socket.

### Service files

| File | Written by | Mode | Read by |
|---|---|---|---|
| `/usr/local/bin/thinkpol` | `service install` | 0755 root | the service manager |
| `/etc/systemd/system/thinkpol.service` | `service install`, `service connect-on-boot` | 0644 | systemd; `service *` (must match exactly) |
| `/Library/LaunchDaemons/org.thinkpol.agent.plist` (macOS) | same | 0644 | launchd; `service *` |
| the `thinkpol` group | `service install` | — | the local API's policy |

### Resolver configuration the node edits

| Where | What | Lifetime |
|---|---|---|
| `/etc/resolv.conf` (Linux, when not on resolved's stub) | replaced, 0644, with the header `# thinkpol: generated while the node runs; the original below is put back when it stops.`, then the node's servers, then the original kept in `#thinkpol-original` comment lines | put back on stop, or at the next start after a crash |
| systemd-resolved (Linux) | over D-Bus, the TUN is the link for every name; nothing on disk | the connection's |
| SCDynamicStore (macOS) | the node's own service DNS key, overrides of the services' DNS, and a backup of the originals in `State:/Network/thinkpol/DNS` | in memory until reboot; put back at the next start after a crash |

### Files the dev tools write

| File | Written by | Mode |
|---|---|---|
| `keys/` | `dev keygen *` | 0700 |
| `space.key`, `recovery.key` | `dev keygen space` | 0600 |
| `space.pub` | `dev keygen space` | 0644 |
| `<name>.key` / `<name>.pub` | `dev keygen node` | 0600 / 0644 |
| `map.bin` | `dev map build`, `dev map rotate` (written aside, then renamed) | 0644 |
| `<name>.geoip` | `dev lists build` (directory 0755) | 0644 |
| the `diag -o` file | `diag` (written aside, then renamed; regular files only) | 0600 |

### Logs

The node writes no log file. The log goes to stderr and into an in-memory ring, which `thinkpol logs` reads (PRD S2). Under launchd, stderr goes nowhere. Under systemd, stderr goes to the journal, which is on disk unless the journal is volatile (RR40). `service install` doesn't make it volatile: PRD S2 gives that to provisioning, at M4.

## Planned, not built

**Planned, not built.** These come from the four tickets' scopes. Each needs the owner's verdict before it starts (ORCHESTRATION.md, "Pre-M2 phase"). The open naming questions are listed last in each part, and the findings they touch are named.

### TP-111: the node's capability ceiling (planned, not built)

| Surface | Proposal |
|---|---|
| setting | a preset, `device` (the default) or `server`; within `server`, separate switches for ingress, egress (with `EgressAllowed`) and relaying |
| where | "the root-owned file from TP-046", plus flags for the lab and development. **That file doesn't exist**: TP-046 shipped env plus flags, and a unit that must match exactly (F1) |
| `-mode` / `THINKPOL_MODE` | `auto` is removed: the map's node kind no longer picks how a node runs. The default changes from `auto` to `device`, which changes an existing flag's meaning |
| at start | a map that asks for more than the ceiling leaves the node down, with a health problem naming what was asked and what is allowed (code not named yet) |
| while running | a map asking for more keeps the last accepted capabilities, takes the rest, and reports the refusal in health and the log. The accepted capabilities are saved, so a restart comes back to them. **Where they are saved isn't named** (a new on-disk file?) |
| macOS | a `server` preset is refused: "server nodes need Linux" |
| docs | runbook: the operator sets the ceiling on each server |

Open naming questions:

- the setting's name (keep `-mode`, or something new);
- the capability switches' spelling (F7);
- the problem code (F5);
- the file name and location (F1);
- where accepted capabilities are kept.

### TP-141: a crashed agent's stderr on devices (planned, not built)

| Surface | Proposal |
|---|---|
| file | one 0600 root file holding a device agent's stderr and panic trace, "in the service's state directory", overwritten on each start. **Path not named.** `state.go` says the state directory holds nothing else (PRD S1), and on Linux `/run/thinkpol` doesn't survive a reboot |
| service definition | a device's plist gets `StandardErrorPath`, and the unit gets a matching stderr setting. A server's is unchanged. This means the device and server definitions differ for the first time, so install has to tell them apart |
| `diag` | shows the previous run's trace (a new field: still schema 1) |
| `status` | a short "the last run crashed" line, or a problem (code not named) |
| PRD S2 | amended: no logs on disk except a device's crash trace |

Open questions:

- the path;
- the field name in `diag`;
- the problem code (F5);
- whether the file holds the whole run's log (the log handler writes to stderr too) and needs a size cap.

### TP-133: `diag` without a running agent (planned, not built)

| Surface | Proposal |
|---|---|
| behaviour | when the local API doesn't answer, root's `diag` reads the host itself and writes the same snapshot |
| output | `agent: "not running"`, with `status`, `tun` and `last_apply` unreadable for that reason. **`Diagnostics` has no `agent` field today**: this adds one, a string, with schema still 1 |
| non-root | an error, not a partial snapshot (exit 1, F4) |
| side effects | none: no lock, no directory made |

Open questions:

- whether the fallback is automatic or needs a flag (e.g. `-offline`): automatic hides an API that is down for another reason;
- the `agent` field's values;
- the exit code when it falls back (F4).

### TP-140: health counts dials that never linked (planned, not built)

| Surface | Proposal |
|---|---|
| health | a dialed node never linked past a deadline raises a problem: `no_link_up`, or a new code |
| health | no DNS upstream to ask raises a problem (a new code) |
| `status`, `diag` | show them with the existing rendering |

Open questions: reuse `no_link_up` or add a code, and the codes' names (F5).

## Consistency findings

Nothing here is fixed by TP-139. They are ordered by what each would cost to change once M2 builds on it: most expensive first. Each finding has a suggested verdict: keep, change or drop. The owner's verdicts go into the ticket's Notes.

### F1. There is no place for a node setting except the environment and flags

The service's definition is a fixed text with one variable (`THINKPOL_CONNECT_ON_BOOT`). `service install`, `service connect-on-boot` and `service uninstall` refuse a definition that differs by a byte ("changed by hand … install again"). So an installed node can't be given `THINKPOL_DNS_UPSTREAM`, `-mode`, a log level or an interface name without breaking connect-on-boot. TP-111 puts its ceiling in "the root-owned file from TP-046", which was never built. TP-048's kill-switch toggle, its allow-LAN option and opt-out, and M2's transport settings all need a home.

- Costs after M2: every M2 setting would be invented separately.
- **Suggested verdict: change.** Decide now: one root-owned node config file, read by `up`, which the service unit points at and the exact-match check ignores, or settings the service stores, like `rules.local`. Then let TP-111 and TP-048 use it.

### F2. Three ways to change a setting, and the tray can reach only one

- Operator settings are env or flags on `up`.
- Connect-on-boot is `service connect-on-boot`: root only, a rewrite of the definition, effective from the next boot. The local API has no call for it.
- The rule preset is `SetRulePreset`: the group may call it, the service stores it in `rules.local`, and it takes effect at once.

PRD D5 and the M5 tray need a connect-on-boot toggle. D4 needs a kill-switch toggle, and D8 needs the CLI to cover everything the tray does. Only the third path works for an unprivileged tray.

- **Suggested verdict: change.** Settings a member toggles (connect-on-boot, the kill switch, allow-LAN, pause) go through the local API and are stored by the service, as the rule preset is. Settings an operator sets go to F1's home.

### F3. `status -json` and `diag` speak different JSON

| | `status -json` | `diag` |
|---|---|---|
| field names | lowerCamelCase (`spaceId`, `mapVersion`) | snake_case (`space_id`, `map_version`) |
| zero values | left out (`removed: false` is absent) | always present |
| schema version | none ("not the contract", localapi doc) | `schema_version: 1` |
| whitespace | protojson inserts random extra spaces so that output isn't byte-stable | same |

Both spell 64-bit numbers as strings (`"mapVersion": "1793188210"`) and enums as `CONNECTION_CONNECTED`, while the text view says `connected`. The same `Status` appears in both, spelled two ways.

- The device harness (TP-082), lab verdicts and later the tray will parse `status -json`.
- **Suggested verdict: change.** Make `status -json` use diag's options (proto names, every field), and call it the `Status` part of the v1 contract. Keep protojson's enum and int64 spelling, but write it down.

### F4. Exit codes: only 0, 1 and 2, and a partial success is 1

- `rules preset everything` stores and enforces the preset (failing closed), yet exits 1 with an error.
- `connect` that comes up without DNS protection exits 1 and prints no status, though the tunnel is up.
- "Not running", "permission denied", "server mode" and a real failure are all 1. A script can tell them apart only by parsing stderr prose, and the CLI never shows the machine code (`server_mode`).
- `service uninstall` with nothing installed exits 0.
- TP-133 adds a "fell back" case. The kill-switch and harness scripts will branch on these.
- **Suggested verdict: change.** Define a small table: for example 0 done, 1 failed, 2 usage, 3 not running, 4 permission denied, 5 done with a warning (print the status, put the warning on stderr). Or keep 0/1/2, make partial successes exit 0 with a warning on stderr, and put the machine code in the message.

### F5. Enumerated strings use four spellings

| Spelling | Where |
|---|---|
| snake_case | health problems (`no_link_up`, `worker_restarted`), refusal codes (`server_mode`), uplink errors, Apply steps (`route_table`), counters (`route_table.routes`) |
| kebab-case | rule presets (`all-but-domestic`), a route's owner in `diag` (`route-table`), flags |
| words with spaces | a skipped item (`inbound link`), the text renderings |
| SCREAMING_CASE | proto enums in JSON (`HEALTH_LEVEL_OK`) |

The same thing appears as `route_table` (a step), `route-table` (an owner) and `route table` (text).

- TP-140, TP-141 and TP-111 add codes, and TP-048 will add more.
- **Suggested verdict: change.** One rule: snake_case for every machine code and enumerated value. Presets and flags are typed by people and stay kebab-case. Rename `route-table` (the owner) and `inbound link` before more readers depend on them.

### F6. Command shapes: getters, setters, verbs and nouns are mixed

- Verbs: `connect`, `disconnect`, `up`, `install`. Nouns: `status`, `spaces`, `logs`, `diag`.
- `up` has no `down`: you stop it with a signal or the service manager.
- `service connect-on-boot [on|off]` shows the value without an argument and sets it with one. `rules preset <name>` only sets, and its value is read through `status`.
- The kill switch will need a third shape unless one is chosen.
- `spaces` lists, but nothing switches (D9 is M5).
- **Suggested verdict: change (small).** Adopt "`<setting> [value]`: no value shows it" for every setting (`rules preset` with no argument prints the current preset), and use the same shape for the kill switch. Keep the verb and noun commands as they are.

### F7. Flag spelling

- One socket has two names: `up -api-socket` and the clients' `-socket`. One variable feeds both.
- Output files: `diag -o` but `dev … -out`.
- Single letters only on `logs` (`-n`, `-f`) and `diag` (`-o`).
- Three boolean styles: Go booleans (`-connect`, `-dns`, `-json`), an on/off string flag (`up -connect-on-boot on|off`, `service install -connect-on-boot on|off`), and a positional argument (`service connect-on-boot on`).
- In `up -h`, every flag's type shows as `value` (go-kernel's binder). Elsewhere it shows `string`, `int` or `duration`, and string defaults are quoted on clients and unquoted on `up`.
- **Suggested verdict: change** before the kill-switch flags. Pick on/off strings or booleans for toggles, rename `diag -o` to `-out` (keeping `-o` as an alias), and make the socket one name, `-socket` everywhere, or `-api-socket` everywhere.

### F8. Settings that a member sets need root, while connect doesn't

Alice, in the group, may connect, disconnect and change the rule preset. She may not set connect-on-boot: "the service is the host's: run this as root (sudo)". PRD D5 is a member's toggle.

- **Suggested verdict: change**, together with F2.

### F9. `permission denied: only root may do that` is shown for any refused call

The refusal's client message is fixed text, whatever the call. On macOS, before TP-094, a group member who passes the directory gate is refused *every* call, `status` included, and is told "only root may do that", which is false and points the wrong way.

- **Suggested verdict: change.** Word the message per call ("the log is root's only"), or make it generic ("your user may not do that: …").

### F10. Usage errors don't say what was wrong

`logs -n 0`, `service install -connect-on-boot maybe`, `service connect-on-boot maybe`, `rules preset` without an argument and `worker` without `-space` print only the synopsis. `up -mode bogus`, though, says `mode "bogus": want auto, device or server`. Its message also carries the go-kernel prefix `config: validation:`.

- **Suggested verdict: change (cheap).** Print one line of why before the synopsis, and drop the prefix.

### F11. `help` goes to stdout and `<cmd> -h` goes to stderr

Both exit 0. `thinkpol help | less` works, but `thinkpol status -h | less` doesn't.

- **Suggested verdict: change (cheap).** Write asked-for help to stdout, and keep usage errors on stderr.

### F12. Output formats: only `status` has a machine form

`connect`, `disconnect` and `rules preset` print the status but take no `-json`. Neither do `spaces`, `logs` and `service connect-on-boot`. `diag` has no human form.

- **Suggested verdict: change (small).** Add `-json` to every command that prints a `Status` or a list, using F3's form. `diag` stays JSON only.

### F13. The CLI and the API differ in small ways

- `WatchStatus` clamps an interval below 250ms without saying so. `-interval 10ms` silently means 250ms.
- `TailLogs` treats `lines: 0` as 100. `logs -n 0` is a usage error.
- The CLI accepts a relative `-socket`. The server requires an absolute path.
- The API returns codes. The CLI shows only prose (see F4).
- `Connect` with `dns_not_protected` returns an error and no status, so a client can't show the state it reached.
- **Suggested verdict: keep, with one change:** `Connect` and `SetRulePreset` return the status together with the warning, so that clients can show both.

### F14. Docs and code disagree

- There is no user-facing CLI reference: README shows only `version`, and the runbook covers the dev and service commands. This file is the first complete list.
- Five env keys appear nowhere but their flag help: `THINKPOL_STATE_DIR`, `THINKPOL_INTERFACE`, `THINKPOL_LINK_MTU`, `THINKPOL_API_SOCKET` and `THINKPOL_API_GROUP`. The `-state` and `-api-socket` flags at least are named in package docs.
- DESIGN.md's package table lists `cmd/thinkpol-tray` and the `admin serve` command as if they existed. Both are planned (TP-086, TP-042). AGENTS.md also names `cmd/thinkpol-tray`.
- `up -log-level`'s help says "logs go to stderr only", but the same lines go to the ring that `thinkpol logs` reads.
- `diag`'s summary, "(root's names entry and other public addresses)", is hard to read.
- TP-139's own inventory puts the connect record (`connect`) in the state directory. It is in `/run/thinkpol` (macOS `/private/var/db/thinkpol`), next to the host lock.
- **Suggested verdict: change (docs only).** Mark planned packages as planned in DESIGN.md, fix the two help texts, and link this file from the README as the CLI reference until one exists.

### F15. PRD S2 and the systemd journal

Under systemd the agent's stderr goes to the journal, which is on disk unless volatile. `service install` doesn't change that: S2 gives it to provisioning, at M4 (RR40). TP-141 adds a deliberate on-disk exception for devices.

- **Suggested verdict: keep** (already tracked as RR40). Note in S2's amendment (TP-141) that the journal is a separate, known gap.

### F16. Status rendering nits

- `re-applied 1 times`.
- On a server, `uplink:` lines up with the workers' columns and lands far to the right.
- Two `udp` public listeners (IPv4 and IPv6) look the same.
- `health: ok` with a peer at `no path yet` (TP-140's case for exits; for a device peer it's expected).
- **Suggested verdict: change (cheap)** for the first three. The fourth is TP-140's.

### F17. `service uninstall` with nothing installed

It exits 0 and says "the group thinkpol stays", even when there is no group.

- **Suggested verdict: keep** the exit 0, because uninstall is idempotent. **Change** the line so it is printed only when the group exists.

### F18. `worker` reads the node's whole config

The hidden `worker` runs `agent.LoadConfig()`, which reads every `THINKPOL_*` variable, but it uses only the log level.

- **Suggested verdict: keep.** It is harmless while validation is deferred, and TP-145 moves env reads to the composition root anyway.

### F19. `dev lists build -only kz` says "(it has 0 others)"

The count is that of the requested lists it found, not of the source's lists. The source in the example has three.

- **Suggested verdict: change** (a one-line bug).

### F20. `rules.local` is 0644 and the blobs are 0600

`rules.local` reveals the member's routing choice. It is safe only because the state directory is expected to be 0700, but `state.go` checks that the directory is not *writable* by others, not that it is unreadable.

- **Suggested verdict: change (cheap).** Write it 0600, like the other private files.

### F21. The planned surface repeats today's open choices

Each of the four planned tickets needs a code, a path or a flag name that F1, F4, F5 and F7 would decide:

- TP-111: the ceiling file, the problem code, and the change of `-mode`'s default from `auto` to `device`;
- TP-141: the trace file's path, its `diag` field and its problem code;
- TP-133: the new `agent` field, and automatic versus explicit fallback;
- TP-140: reuse `no_link_up` or add codes.

- **Suggested verdict: change.** Settle F1, F4, F5 and F7 in the owner's session, then write the answers into those four tickets before they start.
