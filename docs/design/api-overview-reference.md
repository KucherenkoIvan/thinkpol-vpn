# thinkpol-vpn — API overview: CLI and local API reference

The CLI and local API half of the [API overview](api-overview.md) (TP-139), split out to keep each file under the design docs' 50 KB limit. The overview has the summary, the configuration, the on-disk state, the planned surface and the consistency findings (`Fn` below). Where the examples come from: [API overview](api-overview.md), first paragraphs. As there, the code wins where this file disagrees with it.

## CLI

### Dispatch, help and exit codes

Commands are registered one per file in `cmd/thinkpol/` with a space-separated path (`cmd/thinkpol/cli.go`). A group (`dev`, `dev map`, `service`, `rules`) is never a command itself: naming one lists its commands. Flags are Go's `flag` package: a single dash (`-json`; `--json` works too), placed after the command path.

| Invocation | Prints | To | Exit |
|---|---|---|---|
| `thinkpol` (no arguments) | the command list | stderr | 2 |
| `thinkpol help`, `-h`, `-help`, `--help` | the command list | stdout | 0 |
| `thinkpol <group>` (e.g. `dev map`) | that group's commands | stderr | 2 |
| `thinkpol <group> help` | that group's commands | stdout | 0 |
| `thinkpol nope`, `thinkpol dev nope` | `thinkpol: unknown command "dev nope"`, then the list | stderr | 2 |
| `thinkpol <cmd> -h` | synopsis, summary, flags with defaults | stderr | 0 |
| a bad flag | `flag provided but not defined: -bogus`, then synopsis and flags | stderr | 2 |
| wrong arguments | synopsis and summary only, no reason | stderr | 2 |
| any other failure | `thinkpol <cmd>: <message>` | stderr | 1 |
| success | the command's output | stdout | 0 |

The command list (`thinkpol help`):

```
usage: thinkpol <command> [arguments]

commands:
  connect                  connect this device: bring its data plane up on the latest map
  dev keygen node          development tooling: make nodes' ids, map and WireGuard keys
  dev keygen space         development tooling: make a space's id, IPv6 network, signing and recovery keys
  dev lists build          development tooling: build GeoIP list blobs (<out>/<name>.geoip) from a local v2fly geoip.dat or DB-IP Lite CSV; prints the source's attribution
  dev map build            development tooling: build and sign a map from a spec (format: dev map spec)
  dev map inspect          development tooling: verify a map and print its header, and a node's section
  dev map rotate           development tooling: rebuild the deployed map with fresh link credentials and a version past it
  dev map spec             development tooling: print the map spec format, annotated
  diag                     print a JSON snapshot of what the node changed on the host (root's names entry and other public addresses)
  disconnect               disconnect this device: take its data plane down (the service keeps running)
  logs                     print the running node's in-memory log (root only)
  rules preset             switch this device's routing rules to a preset
  service connect-on-boot  show or set whether the service connects this device at boot (off by default); setting it needs root
  service install          run this node as a service (systemd, launchd), started at boot; as root
  service uninstall        stop the service and remove it and its binary (its group and the node's keys and map stay); as root
  spaces                   list the spaces this node is enrolled in
  status                   show the running node's state: connection, space, health, peers
  up                       run this node from the keys and map in its state directory (environment: THINKPOL_*)
  version                  print the version
```

Signals. `up` owns SIGINT and SIGTERM: the go-kernel app shuts down gracefully, and a second signal forces it. SIGHUP re-reads the map. Every other command cancels on the first SIGINT or SIGTERM, and a second one kills it. A `status -watch` or `logs -f` that is interrupted ends cleanly, with exit 0.

### Commands at a glance

| Command | Talks to | Who may run it | Output | Machine-readable |
|---|---|---|---|---|
| `version` | nothing | anyone | one line | no |
| `up` | the host | root (it changes routes, DNS, the firewall) | log lines on stderr | no (logfmt lines) |
| `status` | local API `GetStatus` / `WatchStatus` | root, group | status block | `-json` |
| `connect` | `Connect` | root, group | status block | no |
| `disconnect` | `Disconnect` | root, group | status block | no |
| `spaces` | `ListSpaces` | root, group | one id per line | no |
| `rules preset` | `SetRulePreset` | root, group | status block | no |
| `logs` | `TailLogs` | root | log lines | no |
| `diag` | `Diagnose` | root (whole), group (no host parts) | JSON | always JSON |
| `service install` | the service manager | root | a few lines | no |
| `service uninstall` | the service manager | root | a few lines | no |
| `service connect-on-boot` | the service definition | anyone to show it, root to set it | one line | no |
| `dev keygen node`, `dev keygen space` | files | anyone | file list | no |
| `dev map build`, `dev map rotate`, `dev map inspect`, `dev map spec` | files | anyone | text | no |
| `dev lists build` | files | anyone | table and attribution | no |
| `worker` (hidden) | the supervisor's pipe | the supervisor | none | n/a |

### `version`

Prints the version, the Go version and the platform. The version comes from `-ldflags -X main.version` (`make build`), else the build info, else `dev`. It takes no flags.

```
$ thinkpol version
thinkpol dev go1.26.10 linux/arm64
```

Errors: an extra argument is a usage error (exit 2).

### `up`

Runs the node from its state directory: a device's data plane, or a server's supervisor and workers. It also serves the local API unless `-api-socket` is empty. Configuration comes from the environment, and these flags override it. Each flag's help names its variable (`config.BindFlags` over the `Config` struct in `internal/agent/config.go`).

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-state` | `THINKPOL_STATE_DIR` | `/var/lib/thinkpol` (macOS `/private/var/lib/thinkpol`) | state directory: `node.key`, `space.pub`, `map.bin` |
| `-map` | `THINKPOL_MAP` | empty: `map.bin` in the state directory | the map file |
| `-mode` | `THINKPOL_MODE` | `auto` | `auto` (by the node's kind in the map), `device`, `server` |
| `-log-level` | `THINKPOL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-interface` | `THINKPOL_INTERFACE` | empty: the platform's default (`thinkpol0` on Linux) | the overlay TUN's name, 1–15 printable ASCII characters |
| `-link-mtu` | `THINKPOL_LINK_MTU` | `0` (1500) | MTU under the links, 576–65535 |
| `-map-poll` | `THINKPOL_MAP_POLL` | `5s` | how often the map file is checked (at least 100ms); SIGHUP checks at once |
| `-connect` | `THINKPOL_CONNECT` | `true` | a device connects when it starts; not read when connect-on-boot is set |
| `-connect-on-boot` | `THINKPOL_CONNECT_ON_BOOT` | empty | `on`, `off` or empty: the service's setting (see [`service connect-on-boot`](#service-connect-on-boot)) |
| `-api-socket` | `THINKPOL_API_SOCKET` | `/run/thinkpol-api/api.sock` (macOS `/private/var/db/thinkpol-api/api.sock`; Windows: none) | the local API's socket, an absolute path; empty: no local API |
| `-api-group` | `THINKPOL_API_GROUP` | `thinkpol` | the group (a name or a gid) allowed to use the local API |
| `-dns` | `THINKPOL_DNS` | `true` | run the node's resolver |
| `-dns-upstream` | `THINKPOL_DNS_UPSTREAM` | empty: a device asks what the OS used, an exit asks Quad9, then Cloudflare | IPs or IP:ports, comma-separated |
| `-egress-allowed` | `THINKPOL_EGRESS_ALLOWED` | empty | private prefixes an exit's spaces may still reach |

Synopsis: `thinkpol up [-state dir] [-map file] [-mode auto|device|server] [flags]`. `-h` prints every flag with its variable. The `-api-socket` line, for example:

```
  -api-socket value
    	the local API's socket, in a directory of its own; empty: no local API (env THINKPOL_API_SOCKET) (default /run/thinkpol-api/api.sock)
```

Validation errors are collected and printed together, prefixed `config: validation:`:

```
$ thinkpol up -mode bogus -state /tmp/x
thinkpol up: config: validation: mode "bogus": want auto, device or server
```

The other validation messages (`Config.Validate`):

- `no state directory`
- `link MTU %d: want 576 to 65535, or 0 for the default`
- `connect-on-boot %q: want on, off or empty`
- `connect-on-boot keeps the device's connect choice, which only the local API changes: set an API socket`
- `a device that starts disconnected needs the local API to connect: set an API socket`
- `API socket %q: want an absolute path`
- `egress allowed %q: want IPv4 or IPv6 prefixes like 203.0.113.0/24`
- `DNS upstream %q: want an IP or IP:port`
- `map poll interval %v: want at least 100ms`
- interface name errors

Later errors come from the state directory and the host, for example `another thinkpol agent is running on this host (it holds /run/thinkpol/agent.lock)`, or a `rules.local` that can't be parsed (`…; fix it or remove it (the device then follows the space's rules)`). Exit codes: 0 after a clean stop, 1 for a failure, 2 for an extra argument.

Its output is logfmt lines on stderr, and the same lines go into the in-memory ring that `thinkpol logs` reads (from a lab run):

```
time=2026-10-28T11:50:14.854Z level=INFO msg=connected service=thinkpol space=740e402e696b17850eebc1d43a451bd1
```

### Local API clients: `status`, `connect`, `disconnect`, `spaces`, `rules preset`, `logs`, `diag`

Every one of these takes `-socket path`. Its default is `THINKPOL_API_SOCKET` if that is set, else the platform's default socket, the same one `up -api-socket` defaults to. The client probes the socket first, so a missing service or a caller without access gets a plain message. All of them exit 0 on success, 1 on any refusal or failure, and 2 on a usage error.

Errors that every client can print (`internal/agent/localapi/client.go`, `errors.go`):

| Situation | Message (after `thinkpol <cmd>: `) |
|---|---|
| nothing listens at the socket | `the thinkpol service is not running (nothing listens at /run/thinkpol-api/api.sock)` |
| the socket's directory refuses the caller | `permission denied: the local API at /run/thinkpol-api/api.sock is for root and the members of its group` |
| a call the caller's level doesn't allow | `permission denied: only root may do that` |
| a server refusing a device-only call | `this node is a server: it serves its spaces whenever it runs` |
| the node isn't running its data plane yet | `the node is not running` |
| a data plane that failed to start | `starting the data plane failed at step "tun"; the service's log has the details` |
| a code the client doesn't know (a newer service) | `refused: <code>` |
| any other gRPC failure | `<grpc code>: <message, sanitized>` |

#### `status`

Shows the node's state. Synopsis: `thinkpol status [-socket path] [-json] [-watch] [-interval d]`.

| Flag | Default | Meaning |
|---|---|---|
| `-socket` | see above | the local API's socket |
| `-json` | false | print the status as JSON (protojson defaults; see F3) |
| `-watch` | false | keep printing until interrupted: a blank line between statuses, or one JSON object after another |
| `-interval` | `1s` | how often with `-watch`; the service clamps it to at least 250ms |

A device, disconnected (alice):

```
$ thinkpol status
state:        disconnected
health:       down: disconnected
space:        740e402e696b17850eebc1d43a451bd1, map version 1793188210
mode:         device
rule preset:  space (applies once connected)
```

A device, connected, a few seconds later:

```
$ thinkpol status
state:        connected
health:       ok
space:        740e402e696b17850eebc1d43a451bd1, map version 1793188210
mode:         device
rule preset:  space
overlay:      mtu 1328, ipv6 on, 0 listeners
egresses:     overlay (mtu 1328)
peers:
  3c9da4619392d106  100.64.0.3 fded:8bed:923::3  no path yet  no handshake      rx 0 B    tx 0 B
  431756c42f1667bf  100.64.0.1 fded:8bed:923::1  direct       handshake 2s ago  rx 220 B  tx 276 B
neighbors:
  431756c42f1667bf  up 3s  rtt 27.6ms  udp (dialed active up)
route table:        159 routes, re-applied 1 times
dropped:            router.foreign_source 1
```

A server (root):

```
$ thinkpol status
state:   serving
health:  ok
space:   740e402e696b17850eebc1d43a451bd1, map version 1793188210
mode:    server
workers:
  740e402e696b17850eebc1d43a451bd1  ready 12s ago  1 starts
uplink:                             eth0, ipv4 on, ipv6 off, forwarding on/on
public listeners:
  udp  routed 12  unauthenticated 0  no space 0  overloaded 0  rejected links 0
  udp  routed 0   unauthenticated 0  no space 0  overloaded 0  rejected links 0
```

Other lines appear when they apply:

- `maps refused: N since the node started (the service's log says why)`;
- `retrying: yes, see the service's log`;
- `last apply: failed at <step>`;
- `skipped from the map:`;
- `rule preset: everything (unavailable in this space: failing closed)`;
- `uplink: none (<code>): no space has egress`;
- under `route table:`, the notes `N policy rules of other software come first and may route around the tunnel` and `N routes of other software take overlay addresses around the tunnel`.

`dropped:` lists only drop counters that are nonzero; `status -json` has every counter.

`status -json` (the same device, abridged; the double space after each colon is protojson's own, see F3):

```json
{
  "mode":  "MODE_DEVICE",
  "spaceId":  "740e402e696b17850eebc1d43a451bd1",
  "mapVersion":  "1793188210",
  "connection":  "CONNECTION_CONNECTED",
  "health":  {
    "level":  "HEALTH_LEVEL_OK"
  },
  "dataPlane":  {
    "mtu":  1328,
    "ipv6":  true,
    "peers":  [
      {
        "nodeId":  "431756c42f1667bf",
        "device":  "overlay",
        "addresses":  ["100.64.0.1", "fded:8bed:923::1"],
        "firstHop":  "431756c42f1667bf",
        "lastHandshake":  "2026-10-28T11:50:15.085267719Z",
        "rxBytes":  "220",
        "txBytes":  "276"
      }
    ],
    "counters":  {
      "interface.reapplies":  "1",
      "path.delivered":  "2",
      "route_table.routes":  "159",
      "router.foreign_source":  "1"
    }
  },
  "rulePreset":  "space",
  "rulesEnforced":  true
}
```

The health problem vocabulary (`internal/agent/status.go`): `disconnected`, `removed_from_space`, `starting`, `retrying`, `apply_failed`, `no_link_up`, `neighbor_down`, `entries_skipped`, `worker_down`, `worker_restarted`, `links_rejected`, `rule_preset_unavailable`, `route_table_not_enforced`, `policy_rules_ahead`, `overlay_routes_ahead`, `ipv6_guard_not_enforced`, `ipv6_guard_unsupported`, `dns_not_protected`, `dns_upstreams_stale`, `dns_upstream_refused`.

#### `connect` and `disconnect`

Bring a device's data plane up or down. The service keeps running and keeps following the map. Both print the status once the change is done. The only flag is `-socket`.

```
$ thinkpol connect
state:        connected
health:       ok
space:        740e402e696b17850eebc1d43a451bd1, map version 1793188210
mode:         device
rule preset:  space
overlay:      mtu 1328, ipv6 on, 0 listeners
egresses:     overlay (mtu 1328)
peers:
  3c9da4619392d106  100.64.0.3 fded:8bed:923::3  no path yet  no handshake  rx 0 B  tx 0 B
  431756c42f1667bf  100.64.0.1 fded:8bed:923::1  no path yet  no handshake  rx 0 B  tx 0 B
neighbors:
  431756c42f1667bf  up 0s  rtt 31.4ms  udp (dialed active up)
route table:        159 routes, re-applied 0 times
dropped:            router.foreign_source 1
```

```
$ thinkpol disconnect
state:        disconnected
health:       down: disconnected
space:        740e402e696b17850eebc1d43a451bd1, map version 1793188210
mode:         device
rule preset:  space (applies once connected)
```

Calling either one twice is harmless: a second `disconnect` prints the same block and exits 0.

Errors:

- On a server: `this node is a server: it serves its spaces whenever it runs`.
- A failed start: `starting the data plane failed at step "<step>"; …`. The step is `tun`, `engine`, or an Apply step: `section`, `removals`, `interface`, `devices`, `router`, `route_table`.
- A connect that came up but whose OS may resolve outside the tunnel: `connected, but DNS is not protected: the system may resolve names outside the tunnel (the service's log says why); the tunnel stays up`. It exits 1 and prints no status (F4).

#### `spaces`

Lists the enrolled spaces and marks the active one. A node has one space until TP-049. The only flag is `-socket`.

```
$ thinkpol spaces
740e402e696b17850eebc1d43a451bd1  (active)
```

#### `rules preset`

Switches a device's routing rules to a preset: `space` (the space's own rules), `everything`, or `all-but-domestic`. The service stores the choice in `rules.local`. Synopsis: `thinkpol rules preset [-socket path] <space|everything|all-but-domestic>`. It prints the status. There is no form that shows the current preset: `status` shows it.

```
$ thinkpol rules preset space
state:        connected
health:       ok
…
rule preset:  space
…
```

Errors:

```
$ thinkpol rules preset everything        # the M0 map has no chain
thinkpol rules preset: this space can't build that preset (no chain, or no domestic list): it is kept, and enforced failing closed
$ echo $?
1
$ thinkpol rules preset sometimes
thinkpol rules preset: no such rule preset: space, everything or all-but-domestic
```

After the first error the choice *is* stored and enforced: `status` then shows `health: degraded: rule_preset_unavailable` and `rule preset: everything (unavailable in this space: failing closed)`. On a server, it is refused with the server message.

#### `logs`

Prints the agent's in-memory log ring. Root only. Synopsis: `thinkpol logs [-socket path] [-n lines] [-f]`.

| Flag | Default | Meaning |
|---|---|---|
| `-n` | `100` | how many of the last lines; below 1 is a usage error |
| `-f` | false | keep printing new lines until interrupted |

```
$ thinkpol logs -n 3
time=2026-10-28T11:50:20.756Z level=INFO msg="rule preset set" service=thinkpol preset=everything
time=2026-10-28T11:50:21.210Z level=INFO msg="route table applied" service=thinkpol space=740e402e696b17850eebc1d43a451bd1 routes=56 took=428ms
time=2026-10-28T11:50:22.135Z level=INFO msg="rule preset set" service=thinkpol preset=space
```

When the ring dropped lines before they could be sent, a line `... N lines dropped from the log before they could be sent` comes first. As alice: `thinkpol logs: permission denied: only root may do that`.

#### `diag`

Writes a JSON snapshot of the node's state and of what it changed on the host. It changes nothing. Synopsis: `thinkpol diag [-socket path] [-o file|-]`.

| Flag | Default | Meaning |
|---|---|---|
| `-o` | `-` | write to this file, mode 0600, written beside it and renamed over it; `-` (or empty) prints it |

The JSON is the v1 contract (`schema_version: 1`). It uses the schema's snake_case names and has every field present, with an unset one as its zero value or null. A part the agent couldn't read has only `unreadable` set. Root and the service's user get everything. The group gets `host_parts: false`, with the routes, policy rules, guard and DNS marked unreadable. The group's snapshot, abridged:

```json
{
  "schema_version":  1,
  "taken_at":  "2026-10-28T11:50:23.009313333Z",
  "os":  "linux",
  "agent_version":  "dev",
  "host_parts":  false,
  "status":  { "mode":  "MODE_DEVICE", "space_id":  "740e402e696b17850eebc1d43a451bd1", "map_version":  "1793188210", "connection":  "CONNECTION_CONNECTED", "…": "…" },
  "tun":  { "unreadable":  "", "name":  "thinkpol0", "index":  11, "mtu":  1328, "up":  true, "running":  true,
            "addresses":  ["100.64.0.2/10", "fded:8bed:923::2/48", "fe80::21e2:a03c:5b23:ce92/64"] },
  "last_apply":  {
    "unreadable":  "",
    "started":  "2026-10-28T11:50:14.679812760Z",
    "took":  "0.085776458s",
    "failed":  "",
    "steps":  [ { "step":  "section", "took":  "0.014132875s", "failed":  false }, "…" ]
  },
  "routes":  { "unreadable":  "root only: it names public addresses", "routes":  [], "unrecorded_proto2":  [] },
  "policy_rules":  { "unreadable":  "root only: it names public addresses", "rules":  [] },
  "guard":  { "unreadable":  "root only: it names public addresses", "where":  "", "rules":  null, "exempt":  null, "nftables":  null, "pf":  null },
  "dns":  { "unreadable":  "root only: it names public addresses", "sources":  [] }
}
```

Root's snapshot fills those four parts. An excerpt from the same run:

```json
  "guard":  {
    "unreadable":  "",
    "where":  "nftables table inet thinkpol-guard",
    "present":  true,
    "rules":  { "unreadable":  "", "rules":  [
      { "chain":  "output", "text":  "meta oifname \"lo\" accept", "counted":  false, "packets":  "0", "bytes":  "0", "evaluations":  "0", "states":  "0" },
      "…" ] },
  "dns":  { "unreadable":  "", "sources":  [
      { "name":  "resolv.conf", "unreadable":  "", "present":  true, "resolvers":  [
          { "interface":  "", "scoped":  false, "servers":  ["100.64.0.2", "fded:8bed:923::2"], "domains":  [], "search":  [],
            "order":  0, "flags":  "", "reach":  "", "options":  ["timeout:1", "attempts:1"], "node_written":  true } ] },
      { "name":  "systemd-resolved", "unreadable":  "", "present":  false, "resolvers":  [] } ] }
```

The full schema is the `Diagnostics` message in `proto/thinkpol/localapi/v1/localapi.proto`.

Errors:

```
$ thinkpol diag -o /dev/null
thinkpol diag: /dev/null: not a regular file: refusing to replace it
```

`-o` refuses anything that isn't a regular file, any symlink included.

### `service install`

Run as root, it does the following:

- checks that the node can run from the default state directory;
- creates the `thinkpol` group and adds the installing user;
- copies the running binary to `/usr/local/bin/thinkpol`;
- writes the definition (systemd `/etc/systemd/system/thinkpol.service`, or launchd `/Library/LaunchDaemons/org.thinkpol.agent.plist`);
- starts the service.

Run again, it replaces the binary and restarts the service, and keeps connect-on-boot unless the flag sets it. Synopsis: `thinkpol service install [-connect-on-boot on|off] [-user name]`.

| Flag | Default | Meaning |
|---|---|---|
| `-connect-on-boot` | empty | `on` or `off`; empty: as installed, else `off` |
| `-user` | `$SUDO_USER` unless that is root | added to the `thinkpol` group; empty: no one |

```
$ sudo thinkpol service install        # SUDO_USER=alice
alice is in group thinkpol: the local API is theirs from their next login
installed and started /etc/systemd/system/thinkpol.service (connect-on-boot off)
```

The unit it writes (the whole file; nothing else configures the service):

```ini
# Written by thinkpol service install; thinkpol service uninstall removes it.
# Connect-on-boot: thinkpol service connect-on-boot on|off.
[Unit]
Description=thinkpol node agent
After=network.target systemd-resolved.service
StartLimitIntervalSec=0

[Service]
ExecStart=/usr/local/bin/thinkpol up
# SIGHUP to the agent alone re-reads the map at once; a server's workers
# don't handle it, so never signal the whole unit.
ExecReload=/bin/kill -HUP $MAINPID
Environment=THINKPOL_CONNECT_ON_BOOT=off
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
```

The launchd plist carries the same settings: `ProgramArguments` `up`, `EnvironmentVariables` with only `THINKPOL_CONNECT_ON_BOOT`, `RunAtLoad`, `KeepAlive`, `ThrottleInterval` 5 and `ExitTimeOut` 60. It has no `StandardOutPath` or `StandardErrorPath`.

Errors:

| Situation | Message (after `thinkpol service install: `) | Exit |
|---|---|---|
| not root | `the service is the host's: run this as root (sudo)` | 1 |
| no keys or map yet | `this node can't run yet: state directory: open /var/lib/thinkpol: no such file or directory` | 1 |
| an agent run by hand holds the host lock | `a thinkpol agent runs outside the service (it holds the host lock): stop it, then run this again` | 1 |
| the binary's directory is writable by others | `the service's binary would be in a directory others can change: …` | 1 |
| `-connect-on-boot maybe` | synopsis only | 2 |
| a definition edited by hand | a `warning: … installing anew, connect-on-boot off unless -connect-on-boot says otherwise` line, then it goes on | 0 |

A failed stop or start says what is left: whether the installed service was stopped, that the new definition is on disk, and what the manager reports.

### `service uninstall`

Run as root, it does the following:

- stops the service; the agent takes its data plane down as it stops;
- undoes what a crashed agent left, holding the host lock;
- removes the definition and the binary;
- clears the agent's runtime directories of locks, boot records and sockets.

The group, the state directory, the keys and the map stay. It takes no flags.

```
$ sudo thinkpol service uninstall
stopped and removed /etc/systemd/system/thinkpol.service
the group thinkpol stays; remove it yourself if nothing else uses it
```

With nothing installed it still exits 0 and prints the group line alone. If something other than locks and records is left in a runtime directory, it prints `left in /run/thinkpol, not the agent's locks or boot records: …`. Errors: not root, and an agent run by hand holding the lock, with the same messages as install.

### `service connect-on-boot`

With no argument it shows the installed service's setting. With `on` or `off`, as root, it rewrites the definition and reloads the manager. The running agent isn't restarted: the setting counts from the next boot. A device keeps its last connect or disconnect for the rest of a boot, in the [connect record](api-overview.md#on-disk-state). Synopsis: `thinkpol service connect-on-boot [on|off]`. It has no flags.

```
$ thinkpol service connect-on-boot
connect-on-boot: off
$ sudo thinkpol service connect-on-boot on
connect-on-boot on: from the next boot
```

Errors:

- `the service is not installed`
- `the service is the host's: run this as root (sudo)` (setting it as alice, though she is in the group)
- `the service's definition was changed by hand: /etc/systemd/system/thinkpol.service isn't what thinkpol service install writes; install again`
- an argument other than `on` or `off` is a usage error, exit 2

### `dev keygen node`, `dev keygen space`

Development tooling for a space without a controller (`docs/runbook-pre-controller.md`). Keys are never replaced.

| Command | Flag | Default | Meaning |
|---|---|---|---|
| `dev keygen node [-out dir] <name>...` | `-out` | `keys` | directory for `<name>.key` (0600) and `<name>.pub` (0644) |
| `dev keygen space [-out dir] [-recovery-out dir]` | `-out` | `keys` | directory for `space.key` (0600) and `space.pub` (0644) |
| | `-recovery-out` | `-out` | directory for `recovery.key` (0600), e.g. removable media |

```
$ thinkpol dev keygen space -out keys
space 0f511e930bf30548f2839ae4d6dc7b14, IPv6 fd6f:25b2:b1e9::/48
  keys/space.key  signing key (private)
  keys/space.pub  public keys, for every node
  keys/recovery.key  recovery key (private): move it offline, nothing here needs it
$ thinkpol dev keygen node -out keys server-1 device-a
node server-1, id bb4af31c4ce8d8dd
  keys/server-1.key  private, for server-1 only
  keys/server-1.pub  public, for the map builder
node device-a, id 2c5ca96b4c413151
  keys/device-a.key  private, for device-a only
  keys/device-a.pub  public, for the map builder
$ thinkpol dev keygen node -out keys device-a
thinkpol dev keygen node: keys/device-a.key exists; keys are never replaced
```

`dev keygen node` with no names is a usage error.

### `dev map build`, `dev map rotate`, `dev map inspect`, `dev map spec`

| Command | Flag | Default | Meaning |
|---|---|---|---|
| `dev map build [flags] <spec.yaml>` | `-keys` | `keys` | `space.key`, `space.pub` and every node's `<name>.pub` |
| | `-out` | `map.bin` | the signed map (0644) |
| | `-version` | `0`: the current Unix time, or one past the map in `-out` if higher | the map's version |
| | `-insecure-secrets-seed` | empty | derive link secrets from a seed; refused unless the spec says `lab: true` |
| `dev map rotate [-keys dir] [-out file] <spec.yaml>` | `-keys`, `-out` | as above | rebuild with fresh link secrets and a version past the map in `-out` |
| `dev map inspect [-keys dir] [-node-key file] <map.bin>` | `-keys` | `keys` | verify against `space.pub`; `<name>.pub` files name the node ids |
| | `-node-key` | empty | a node's `<name>.key`: also print its section |
| `dev map spec` | — | — | print the annotated spec format |

Spec values may use `${NAME}` from the environment.

```
$ thinkpol dev map build -keys keys -out map.bin -version 5 lab/maps/m0.yaml
map version 5 of space 0f511e930bf30548f2839ae4d6dc7b14: 3 nodes, 66130 bytes, written to map.bin
$ thinkpol dev map rotate -keys keys -out map.bin lab/maps/m0.yaml
map version 1793188125 of space 0f511e930bf30548f2839ae4d6dc7b14: 3 nodes, 66134 bytes, written to map.bin
rotate: copy map.bin to every node's map file; every node takes the same file, within its map poll or on SIGHUP: server-1, device-a, device-b
$ thinkpol dev map inspect -keys keys -node-key keys/device-a.key map.bin
valid map, signed by the space key in keys/space.pub
space: 0f511e930bf30548f2839ae4d6dc7b14
key epoch: 0
version: 5
signing key: dccb2c4b3aa7793297f9b0942fe43dae67ebabd040ce9df446ad8eee1866a8a6
recovery key: 3f2d91126bb686f86b06057686b8f9f91f9bd5d8d582cbf8379ec9d506b4d9d3
blobs: none
sections: 8
size: 66130 bytes

section for keys/device-a.key
node: 2c5ca96b4c413151 (device-a)
kind: device
min reader: 1
ipv4: 100.64.0.2 in 100.64.0.0/10
ipv6: fd6f:25b2:b1e9::2 in fd6f:25b2:b1e9::/48
listeners: none
peers:
  - id: bb4af31c4ce8d8dd (server-1)
    wireguard key: 106a991ed3b3f00ba8a460b92b5ae61ea493588e8a9b458b41346512f811c732
    addresses: 100.64.0.1, fd6f:25b2:b1e9::1
    first hops:
      - bb4af31c4ce8d8dd (server-1)
  …
links:
  - peer: bb4af31c4ce8d8dd (server-1)
    endpoints:
      - udp://192.0.2.10:4500, credential 32 bytes, sha256 7fc237b9…
      - udp://[2001:db8::10]:4500, credential 32 bytes, sha256 7fc237b9…
inbound: none
routes: none
blobs: none
$ thinkpol dev map spec | head -4
# thinkpol development tooling: the map spec format.
#
# A spec lists a space's nodes and the paths between them; everything else
# in the map is derived from them.
```

Errors seen:

- `thinkpol dev map build: lab/maps/m0.yaml: an insecure secrets seed is for lab specs only (lab: true): the seed gives away every link`
- `thinkpol dev map build: open missing.yaml: no such file or directory`
- `<map> is not a valid map of space <id>: …`
- `…: no section for this node key`
- the spec parser's errors, which name the spec's line

### `dev lists build`

Builds GeoIP list blobs from a local v2fly `geoip.dat` or DB-IP Lite CSV, and prints the source's attribution. Synopsis: `thinkpol dev lists build [-format v2fly|dbip] [-only ru,by] [-out dir] <source>`.

| Flag | Default | Meaning |
|---|---|---|
| `-format` | from the file name: `*.dat`, `*.csv`, optionally `.gz` | `v2fly` or `dbip` |
| `-only` | every list in the source | comma-separated list names, case-insensitive |
| `-out` | `.` | directory for `<name>.geoip` (0644) |

```
$ thinkpol dev lists build -out lists dbip-country-lite.csv
  name                                                            sha256  bytes  v4 in  v4 out  v6 in  v6 out
    by  db261e9f78a5b7207ed4f5bd46fd4c7149f787885e4581e453838d132688f613     11      1       1      0       0
    ru  da1dd1e916249f1ede71626e196641289231f0e47fcedac975561c2347b4b307     19      2       2      1       1
    zz  e14a079282a12451aa0c989f4c7047159a31158296d5a5dbbca491ab1bc6f83a      7      0       0      0       0

IP Geolocation by DB-IP (CC BY 4.0): https://db-ip.com
```

Warnings go to stderr, for example `warning: zz: left out 1 IPv6 entries overlapping the IPv4-mapped range ::ffff:0:0/96`. Errors:

- `lists: no such list in the source: "kz" (it has 0 others)` (see F19)
- `lists: can't tell the format of "source.mmdb" from its name`

### `worker` (hidden)

Synopsis: `thinkpol worker -space <id>`. It runs one space's sandboxed worker. Only a server's supervisor starts it, with its pipe on stdin and stdout, and `THINKPOL_LOG_LEVEL` in its environment. It is left out of every listing but runs if typed, and without `-space` it prints its synopsis and exits 2. It reads the whole node config from the environment and uses only the log level.

## Local API

The gRPC service `thinkpol.localapi.v1.LocalService` (`proto/thinkpol/localapi/v1/localapi.proto`, server in `internal/agent/localapi/`). Its documentation is the package doc and [desktop client](desktop-client.md#the-local-api).

### Socket and gates

| | Linux | macOS | Windows |
|---|---|---|---|
| socket | `/run/thinkpol-api/api.sock` | `/private/var/db/thinkpol-api/api.sock` | none yet (named pipe, TP-047) |
| directory | 0750 root:`thinkpol` (0700 without the group) | same | — |
| socket mode | 0660 root:`thinkpol` (0600 without the group) | same | — |
| lock | `api.lock`, 0600, next to the socket | same | — |
| peer credentials | `SO_PEERCRED` + `SO_PEERGROUPS` | `LOCAL_PEERCRED` (the login groups, first 16 only: TP-094) | — |

The gates work as follows:

1. **The directory.** Only root, the service's user and the group can reach the socket. Anyone else fails at `connect()`, and the CLI says `permission denied: the local API at … is for root and the members of its group`.
2. **Each call.** The caller's kernel-recorded credentials are checked against `methodAccess` (`internal/agent/localapi/auth.go`). Root and the service's user have `AccessAdmin`. Members of the group have `AccessControl`. Anyone else has `AccessNone`. A call missing from the table needs `AccessAdmin`.

Limits: 32 connections and 16 calls per connection. All watchers share one status snapshot, taken at most every 250ms. If the API can't serve, the node runs on and retries every 10s.

### Calls

| Call | Kind | Needs | Request | Response | Refusals |
|---|---|---|---|---|---|
| `GetStatus` | unary | control | `{}` | `{ status: Status }` | — |
| `WatchStatus` | server stream | control | `{ interval: Duration }` (unset: 1s; at least 250ms) | stream of `{ status: Status }`, the first at once | — |
| `Connect` | unary | control | `{}` | `{ status: Status }` once up | `server_mode`, `not_running`, `dns_not_protected`, `start_failed:<step>` |
| `Disconnect` | unary | control | `{}` | `{ status: Status }` once down | `server_mode`, `not_running` |
| `ListSpaces` | unary | control | `{}` | `{ spaces: [ { id, active } ] }` (always one, active) | — |
| `SetRulePreset` | unary | control | `{ preset: string }` | `{ status: Status }` | `unknown_rule_preset`, `rule_preset_unavailable` (stored anyway), `server_mode` |
| `TailLogs` | server stream | admin | `{ lines: uint32 (0: 100), follow: bool }` | stream of `{ lines: [string], missed: uint64 }` | — |
| `Diagnose` | unary | control (host parts: admin) | `{}` | `{ diagnostics: Diagnostics }` | — |

Any call can also fail with `permission_denied`.

Refusals travel as go-kernel domain error codes over gRPC status codes. The client maps them back to errors that `errors.Is` can test, with a message for a person:

| Code | gRPC code | Client message |
|---|---|---|
| `permission_denied` | PermissionDenied | permission denied: only root may do that |
| `server_mode` | FailedPrecondition | this node is a server: it serves its spaces whenever it runs |
| `not_running` | Unavailable | the node is not running |
| `rule_preset_unavailable` | FailedPrecondition | this space can't build that preset (no chain, or no domestic list): it is kept, and enforced failing closed |
| `unknown_rule_preset` | InvalidArgument | no such rule preset: space, everything or all-but-domestic |
| `dns_not_protected` | FailedPrecondition | connected, but DNS is not protected: … the tunnel stays up |
| `start_failed:<step>` | (the interceptor's) | starting the data plane failed at step "<step>"; the service's log has the details |

### `Status`

`Status` is the shape that `status`, `connect`, `disconnect` and `rules preset` render, and it is inside `Diagnostics`. Fields:

- `mode`: `MODE_DEVICE`, `MODE_SERVER`, or `MODE_UNSPECIFIED` when the node was removed and its kind is unknown;
- `space_id`, `map_version`, `removed`;
- `connection`: `DISCONNECTED`, `CONNECTING`, `CONNECTED` or `SERVING`;
- `retrying`;
- `health`: a level (`OK`, `DEGRADED`, `DOWN`) and its problems;
- `data_plane`: MTU, IPv6 and why it is off, last Apply error, peers, neighbors and their links, egresses, skipped entries, listeners, and counters by name;
- `workers`, `public_listeners`, `uplink`: on a server;
- `rule_preset`, `rules_enforced`, `rule_preset_unavailable`;
- `maps_refused`.

Nothing in it is a public address, a key or a secret. Nodes and spaces are opaque hex ids, and the addresses are the overlay's. Every string is sanitized by the server and again by the client.

### `Diagnostics`

`schema_version` (1), `taken_at`, `os`, `agent_version`, `host_parts`, `status`, `tun`, `last_apply`, `routes`, `policy_rules`, `guard`, `dns`. The last four are host parts: root's only, because they name public addresses. The schema version is bumped when a field is removed or renamed or changes type or meaning. An added field doesn't bump it.
