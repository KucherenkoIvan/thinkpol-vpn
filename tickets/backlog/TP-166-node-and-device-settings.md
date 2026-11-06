---
id: TP-166
title: "Node and device settings: the node file and the member's toggles"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
needs_human: macos
depends_on: []
refs: [D4, D5, S1, docs/design/configuration.md#three-levels, docs/design/configuration.md#precedence-and-narrowing]
owner: ""
branch: ""
---

## Goal
Every setting has one designed home. An operator's settings live in one root-owned node file that `up` reads; a member's toggles on a device live in a small file the service writes through the local API. Connect-on-boot becomes a member's toggle, so the tray and the CLI can change it without root. TP-111's ceiling and TP-048's kill switch then build on these instead of inventing their own (TP-139 findings F1, F2, F8).

## Scope
- **The node file** ([configuration](../../docs/design/configuration.md#node-level)): one root-owned file in the state directory, 0600 in the 0700 directory, `key = value` lines. It holds operating settings only (mode, interface, link MTU, DNS upstream, and the keys TP-111 and TP-048 add), nothing about members, no history. `up` reads it at start. Name the file and its keys, and document them in the `agent` package doc and the runbook.
- **Precedence:** flags, then env, then the node file, then defaults. The map can only narrow what the node allows.
- **Unknown keys and bad values:** `up` exits with EX_CONFIG (78) and names the key or the value. The exit-code table is TP-167's; if it hasn't landed, use 78 here and TP-167 takes it over.
- **The device settings store** ([configuration](../../docs/design/configuration.md#device-level)): a small file next to the node file, written only by the service, 0600, `key = value`. It replaces `rules.local`: the first start that finds `rules.local` carries its preset over and removes it, and says so in the log. A store that can't be read stops the node from starting, as `rules.local` does today.
- **Connect-on-boot as a member's toggle:** a local API call to show and set it (access: the group), stored in the device store. The service always starts at boot, and the stored toggle decides whether it connects. `service connect-on-boot` and `service install -connect-on-boot` become clients of the same setting, or are removed with a message saying what replaced them; the service definition no longer carries `THINKPOL_CONNECT_ON_BOOT`.
- **Drop-ins:** Linux systemd drop-ins are unsupported. `diag` reports any `thinkpol.service.d/*.conf` it finds (a new field, following the JSON convention of TP-168).
- docs/design/configuration.md and the `agent`, `service` and `localapi` package docs updated with what was built, in the same branch.

## Out of scope
- The kill switch, allow-LAN and pause toggles themselves: TP-048 adds them to the device store this ticket builds.
- The capability ceiling: TP-111 adds it to the node file.
- Showing a setting's effective value and its source, per-space settings, a network-level minimum: open questions in docs/design/configuration.md.
- Node groups: a proposal (TP-035).

## Acceptance
- [ ] unit tests: the node file parser (comments, blank lines, quoting if any, duplicate keys, unknown keys, bad values) and precedence (flag over env over file over default), each case a table row
- [ ] unit tests: an unknown key or a bad value makes `up` exit 78 and the message names it
- [ ] unit test: a state directory with `rules.local` and no device store starts with the same preset, the store written 0600, `rules.local` gone
- [ ] lab (Linux): a node started with only a node file runs with its settings; the same key given as env or flag wins over it (`thinkpol status` shows the result)
- [ ] lab (Linux): `alice`, in the group, sets connect-on-boot through the CLI without root; after a service restart that counts as a boot, the node connects or stays down as she set it
- [ ] lab (Linux): a drop-in under `thinkpol.service.d/` appears in `diag`
- [ ] macOS device checklist: a member of the group (not root) turns connect-on-boot on with the CLI; after a reboot the node connects; off, and after a reboot it stays down (results recorded in Notes)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07 (findings F1, F2, F8; verdicts in docs/design/api-overview.md "Verdicts").
- Owner decisions (2026-11-07): three levels; node file root-owned 0600 in a 0700 directory, operating settings only; precedence flags > env > file > defaults; the map only narrows; device toggles through the local API by a member of the access group, stored next to the node file, replacing `rules.local`; connect-on-boot a member's toggle; flat `key = value` files, JSON only where nesting is really needed; drop-ins unsupported, reported by `diag`.
- TP-111 and TP-048 depend on this ticket. TP-167's F20 item (`rules.local` written 0600) is moot if this ticket lands first.
- Which settings take effect at once and which at the next start is to be decided per setting; record each decision in docs/design/configuration.md "When a change takes effect".

## Log
- 2026-11-07 created in backlog
