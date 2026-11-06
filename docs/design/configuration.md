# thinkpol-vpn — Configuration design

Where a setting lives, who may change it, and which value wins. Decided in the owner's session on the API overview's findings F1, F2 and F8 ([verdicts](api-overview.md#verdicts-owner-2026-11-07)). Most of it is not built yet: today a node reads only its environment and flags, and the rule preset is the one setting the service stores (TP-166 builds the rest). The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

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
- the capability ceiling of TP-111;
- the kill switch's defaults.

The file is root-owned, 0600, in the 0700 state directory. It holds operating settings only: nothing about members, no history (S1). `up` reads it at start. Its name is TP-166's to choose.

### Device level

The member's toggles on a device-type node (owner, 2026-11-07): connect-on-boot, the kill switch, allow-LAN, pause and the rule preset. A member of the access group changes them through the local API, from the tray or the CLI, and the service stores them in a small file next to the node file. That file replaces today's `rules.local`, and the first start after the change carries the stored preset over.

**Connect-on-boot is a member's toggle** (owner, 2026-11-07). The service always starts at boot, and the stored toggle decides whether it connects. Changing it needs no root, and no longer rewrites the service definition.

## Precedence and narrowing

For a node setting the first source that sets it wins (owner, 2026-11-07):

1. flags on `up`;
2. the environment (`THINKPOL_*`);
3. the node file;
4. the built-in default.

The levels then combine by narrowing:

- **The map can only narrow what the node allows.** A map that asks for more than the node's ceiling is refused, as TP-111 decided (PRD Decisions, "The node's own configuration caps the map").
- **Device toggles choose within what the node and the map allow** (owner, 2026-11-07).

## File formats

- **Flat settings use `key = value` lines** (ini or `.cfg` style), readable and editable by a person (owner, 2026-11-07). The node file and the device file are both flat.
- **JSON only where nesting is really needed.**
- **An unknown key is an error** (TP-166): `up` exits with EX_CONFIG (78) and names the key, so a typo never reads as a default.
- **Linux systemd drop-ins are unsupported** (owner, 2026-11-07). `diag` reports one if it finds it, since a drop-in can set `THINKPOL_*` variables behind the node file's back.

## When a change takes effect

| Setting | Level | Takes effect |
|---|---|---|
| rule preset | device | at once (as today) |
| connect-on-boot | device | at the next boot |
| kill switch, allow-LAN, pause | device | to be decided per setting (TP-048) |
| node file settings | node | at the next start of `up`; whether any is reloaded while running is to be decided per setting |
| capability ceiling lowered under a running map | node | refused and reported, as TP-111 handles a map asking for more |

## Node groups (proposal)

**Proposal, not confirmed by the owner.** Node groups are planned, with hop groups and the controller, and may carry settings too. The orchestrator's recommendation: groups are a controller-side abstraction. Settings resolve as space defaults, then the group, then the node, and the result is compiled into each node's part of the map. Nodes never see groups, only resolved values (S1). The proposal waits for the owner's answer (TP-035).

## Keys

Keys stay as designed (owner, 2026-11-07): generated on the node, kept in the root-only state directory, never copied off. They are not settings and never go in either file. Key rotation, revoking a seized node and sealing device keys in the OS keystore are documented now and built after the concept is proven ([node safety](security.md#node-safety)).

## Open questions

From the orchestrator's review, not decided:

- How to show a setting's effective value and the source it came from.
- Per-space settings on a node that serves several spaces, and a shared node owner's ceiling over a guest space.
- Per-link transport settings living in the map.
- Secrets never in config files.
- A schema version for the files, and unknown-key handling (EX_CONFIG naming the key).
- A network-level minimum the admin can require (e.g. the kill switch on) that a member can't turn off.
- The initial settings an invite carries.
- Settings per OS user versus per device on a shared computer.
- Windows paths and ACLs for both files (M5).
