# thinkpol-vpn — Configuration design

Where a setting lives, who may change it, and which value wins. Decided in the owner's session on the API overview's findings F1, F2 and F8 ([verdicts](api-overview.md#verdicts-owner-2026-11-07)). TP-166 built the node file and the device file, TP-048 the kill switch's toggles; the capability ceiling (TP-183) is still to come. The mechanism is in the `agent` package doc ("Configuration and logs", "A device's connection"). The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Three levels

Configuration has three levels (owner, 2026-11-07). Each narrows the one above it, never widens it.

| Level | Who sets it | Where it lives | What it holds |
|---|---|---|---|
| Network (the space) | the admin, through the controller | the signed map | everything the space decides; each node gets only its own part ([the signed map](control-plane.md#the-signed-map)) |
| Node | the operator, as root | one root-owned file in the node's state directory | how this machine runs: operating settings only |
| Device | a member, through the local API | a small file the service writes, next to the node file | the member's toggles on a device-type node |

### Network level

The signed map, as designed. Each node opens only its own section (S1). Nothing here changes it.

### Node level

Operator settings, in one file (owner, 2026-11-07):

- the mode, the interface, the link MTU, the DNS upstream;
- the capability ceiling of TP-183 (after the MVP);
- the kill switch's defaults.

The file is root-owned, 0600, in the 0700 state directory; `up` refuses (exit 78) one others may read or another user owns. It holds operating settings only: nothing about members, no history (S1). `up` reads it at start. It is **`node.json`** in the state directory (TP-166), written by hand or by provisioning, never by the agent. Its keys, each optional, are `up`'s flags in snake_case:

| Key | Type | Flag | Default |
|---|---|---|---|
| `mode` | `"device"` or `"server"`; never the map's node kind (TP-111). A device runs no server's section: one whose map makes it a server carries nothing and leaves the host alone (`mode_mismatch`) | `-mode` | `"device"` |
| `interface` | string, a TUN name | `-interface` | the platform's |
| `link_mtu` | whole number, 576 to 65535; 0 is the default | `-link-mtu` | 1500 |
| `log_level` | `"debug"`, `"info"`, `"warn"` or `"error"` | `-log-level` | `"info"` |
| `map_poll` | duration string, at least `"100ms"` | `-map-poll` | `"5s"` |
| `dns` | true or false | `-dns` | true |
| `dns_upstream` | list of `"IP"` or `"IP:port"` | `-dns-upstream` | a device: what the OS used; an exit: public resolvers |
| `egress_allowed` | list of prefixes | `-egress-allowed` | none |
| `kill_switch` | true or false: the device's kill switch until a member sets it | `-kill-switch` | false (PRD D4) |
| `allow_lan` | true or false: whether the kill switch lets the LAN out, until a member sets it | `-allow-lan` | false |
| `fail_closed_after_crash` | true or false: the crash posture (under the "everything" and "all but domestic" presets the kill switch's rules are in place while the connection is meant up, the toggle off, so a crash leaves them); false opts out | `-fail-closed-after-crash` | true |

What says where the node's files are (`-state`, `-map`, `-api-socket`, `-api-group`) or how it is run (`-service`, `-connect`) is not in the file.

### Device level

The member's toggles on a device-type node (owner, 2026-11-07): connect-on-boot, the kill switch, allow-LAN, pause and the rule preset. A member of the access group changes them through the local API, from the tray or the CLI, and the service stores them in a small file next to the node file. That file replaced `rules.local` (TP-166), and the first start after the change carries the stored preset over.

**Connect-on-boot is a member's toggle** (owner, 2026-11-07). The service always starts at boot, and the stored toggle decides whether it connects. Changing it needs no root, and no longer rewrites the service definition.

The file is **`device.json`** in the state directory (TP-166), 0600, written atomically by the service with every key (the kill switch's once a member set them), and by nothing else:

| Key | Type | Set by | Default |
|---|---|---|---|
| `connect_on_boot` | true or false | `thinkpol connect-on-boot on\|off` (local API `SetConnectOnBoot`) | false (PRD D5) |
| `rule_preset` | `"space"`, `"everything"` or `"all-but-domestic"` | `thinkpol rules preset` (`SetRulePreset`) | `"space"` |
| `rules` | list of the device's own rules, `"match -> action"` | not yet settable through the API | none |
| `kill_switch` | true or false; written once a member set it, until then the node's `kill_switch` holds | `thinkpol kill-switch on\|off` (`SetKillSwitch`) | the node's (false) |
| `allow_lan` | true or false; written once a member set it, until then the node's `allow_lan` holds | `thinkpol allow-lan on\|off` (`SetAllowLAN`) | the node's (false) |

The service definition runs `thinkpol up -service` and carries no setting. `service connect-on-boot` and `service install -connect-on-boot` are refused with a message naming `thinkpol connect-on-boot`; an install over a definition that still carries `THINKPOL_CONNECT_ON_BOOT` says the setting moved and is off until a member turns it on: an old definition's "on" is not carried over (owner, 2026-11-07); turn it on again with `thinkpol connect-on-boot on`. `up` refuses to start (exit 78) while `THINKPOL_CONNECT_ON_BOOT` is in its environment, which only an older definition sets: run `thinkpol service install` to replace it. The first start that finds a `rules.local` (and no `device.json`) writes its preset and rules into `device.json`, removes `rules.local` and logs it. A `device.json` that can't be read or parsed stops the node from starting, as `rules.local` did; so an older binary refuses a `device.json` holding keys it doesn't know, and a rollback needs the file removed (or the newer binary installed again).

## Precedence and narrowing

For a node setting the first source that sets it wins (owner, 2026-11-07):

1. flags on `up`;
2. the environment (`THINKPOL_*`);
3. the node file;
4. the built-in default.

A flag given its default value, or a variable set to the empty string, still counts as set (TP-166). A bad value in the node file stops `up` even when a flag or a variable overrides it: the file is the operator's, and a mistake in it is never passed over.

The levels then combine by narrowing:

- **The map can only narrow what the node allows.** A map that asks for more than the node's ceiling is refused, as the owner decided (2026-10-18), built in TP-183 (PRD Decisions, "The node's own configuration caps the map").
- **Device toggles choose within what the node and the map allow** (owner, 2026-11-07).

## File formats

- **One format, JSON,** for the node file and the device file alike (owner, 2026-11-07). Nesting is expected (TP-183's ceiling holds lists, a node that serves several spaces needs settings per space, allow-LAN takes prefixes), and one format is simpler than two. JSON has no comments, so the CLI reference lists every key and its default (TP-167).
- **An unknown key is an error** (TP-166): `up` exits with EX_CONFIG (78) and names the key, so a typo never reads as a default. So are a key given twice (encoding/json would keep the last), a key of another case (encoding/json would match it), a null (encoding/json would read it as the default: leave the key out instead), a value of the wrong type or out of range, invalid JSON, more than one object, and an empty file (`{}` is a file without settings). The same strict reading applies to `device.json`, where a mistake stops the node from starting.
- **Linux systemd drop-ins are unsupported** (owner, 2026-11-07). `diag` reports one if it finds it, since a drop-in can set `THINKPOL_*` variables behind the node file's back: `service_drop_ins.paths` lists every `thinkpol.service.d/*.conf` and `service.d/*.conf` on systemd's system unit search path, in its order (`systemctl set-property` writes under `/etc/systemd/system.control`) (TP-166), to the group too.

## When a change takes effect

| Setting | Level | Takes effect |
|---|---|---|
| rule preset | device | at once (as today) |
| connect-on-boot | device | at the next boot; a start later in the same boot, and the running node, are left as they are |
| kill switch, allow-LAN | device | at once: the call returns once the node put the kill switch in place or removed it (TP-048) |
| pause | device | not built (proposed as its own ticket) |
| node file settings | node | at the next start of `up` (TP-166: none is reloaded while running; SIGHUP re-reads only the map) |
| capability ceiling lowered under a running map | node | refused and reported, as TP-183 handles a map asking for more |

## Node groups (proposal)

**Proposal, not confirmed by the owner.** Node groups are planned, with hop groups and the controller, and may carry settings too. The orchestrator's recommendation: groups are a controller-side abstraction. Settings resolve as space defaults, then the group, then the node, and the result is compiled into each node's part of the map. Nodes never see groups, only resolved values (S1). The proposal waits for the owner's answer (TP-035).

## Keys

Keys stay as designed (owner, 2026-11-07): generated on the node, kept in the root-only state directory, never copied off. They are not settings and never go in either file. Key rotation, revoking a seized node and sealing device keys in the OS keystore are documented now and built after the concept is proven ([node safety](security.md#node-safety)).

## Open questions

From the orchestrator's review, not decided:

- How to show a setting's effective value and the source it came from.
- Per-space settings on a node that serves several spaces, and a shared node owner's ceiling over a guest space.
- Per-link transport settings living in the map.
- A schema version for the files (unknown keys are refused, TP-166).
- A network-level minimum the admin can require (e.g. the kill switch on) that a member can't turn off.
- The initial settings an invite carries.
- Settings per OS user versus per device on a shared computer.
- Windows paths and ACLs for both files (M5).
