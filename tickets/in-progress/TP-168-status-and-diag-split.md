---
id: TP-168
title: "`status -json` with `schema_version`"
milestone: M2
area: cmd
stream: clients
repo: thinkpol-vpn
size: S
depends_on: []
refs: [S1, docs/design/api-overview.md#verdicts-owner-2026-11-07, docs/design/desktop-client.md#the-local-api]
owner: "agent-tp-168"
branch: "tp-168-status-and-diag-split"
---

## Goal
`status` has a machine form the device harness, lab verdicts and later the tray can parse: the service's local state, fast and with no network access, in one JSON convention (TP-139 finding F12; F3's `status` half).

## Scope
- **`status`:** interface, spaces, links and their state, health, toggles, from the service's state only. No network access.
- **One JSON convention:** snake_case field names, every field present, `schema_version`, opt-in with `-json`. Human output stays text. Write the convention down (the `localapi` package doc) and say which part is the v1 contract.
- docs/design/api-overview-reference.md updated for `status`.

## Out of scope
- `-json` on the other commands: TP-181, using this convention.
- `diag` without a running agent: TP-133.
- User-defined diag scripts: TP-171.
- `diag`'s network checks, its redaction and the shareable report: TP-182 (after the MVP).

## Acceptance
- [x] unit test: `status -json` has snake_case field names, zero values present and `schema_version` set (`TestStatusJSONHasEveryFieldBySchemaName`, `TestStatusJSONSaysTheClientsSchema`, `TestJSONIsByteStable`)
- [x] unit test: `status` makes no network call (a test transport that fails any dial) (`TestStatusReachesOnlyTheLocalAPI`)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07 (owner decision on F3 and F12; docs/design/api-overview.md "Verdicts").
- Overlaps TP-133 (`diag` without a running agent): TP-133's new `agent` field follows this convention; whichever starts second merges the other first.
- TP-181 adds `-json` elsewhere in this convention and reuses this ticket's output code.
- After the MVP, to be decided: user-defined diag scripts over an SDK (TP-171).
- This ticket stays on the MVP path only if TP-086 has the tray parse the CLI rather than the local API (open, 2026-11-07).
- Split 2026-11-07 (owner's MVP cut): the network-reaching `diag` and the redacted report moved to TP-182.

- **Decisions (implementation, 2026-11-09).**
  - One JSON writer for `status -json` and `diag` (localapi `writeJSON`): protojson with the proto names and every field, re-indented with `encoding/json` so the bytes are stable (protojson randomizes its whitespace per build). The convention and what the v1 contract covers are in the localapi package doc, "JSON".
  - One schema version for every JSON document, `localapi.SchemaVersion` (was `DiagSchemaVersion`, renamed; still 1). `Status` gets `schema_version` (field 19): the service sets it, and `status -json` stamps the CLI's own, because the JSON holds the fields the CLI's schema knows. The status inside `diag` carries the service's.
  - `DataPlane.interface` (field 11): the TUN's name, from the engine (`agent.Status.Interface`); the text form prints an `interface:` line before `overlay:` (the lab's `overlay: +mtu` regex is untouched).
  - Enums keep protojson's spelling (`CONNECTION_CONNECTED`), 64-bit integers are strings: the F3 verdict said keep them and write them down. This sits against the naming verdict's "enumerated values are snake_case"; changing it would be a schema bump, so it is for TP-181 or the owner to reopen.
  - "No network call": `localapi.DialWith(path, Dialer)` opens every connection the client makes, the probe and gRPC's, through one dialer; the CLI's `env.dial` sets it. The test's dialer lets through only `unix <socket>` and fails anything else, and the fake node fails the test if `status` asks for anything but the status (`Diagnose` reads the host). What it can't see: code that calls `net.Dial` around the dialer.
- **What TP-200 can read from `status -json` instead of logs** (skimmed lab/*_test.go): mode (`mode`; the lab greps `mode=device`); `mode_mismatch`, `no_link_up`, `neighbor_down`, `exit_no_handshake`, `dns_not_protected`, `dns_upstream_refused` and every other problem code (`health.level`, `health.problems`); connected or not (`connection`); links and their state (`data_plane.neighbors[].up`, `.links[].transport/dialed/active/up`); handshakes (`data_plane.peers[].last_handshake`); the map version followed and whether its Apply failed (`map_version`, `data_plane.last_apply_error`); the overlay MTU (`data_plane.mtu`; lab/settings_test.go greps the text); the TUN (`data_plane.interface`); counters (`data_plane.counters`; lab/routetable_test.go already reads them); rule preset (`rule_preset`, `rules_enforced`, `rule_preset_unavailable`); toggles (`connect_on_boot`); a server's workers, uplink (`uplink.ipv4/ipv6/forwarding4/forwarding6`, the lab greps `egress_ipv4=on`) and public listeners. Not in the status, so still log lines or a new field: a server worker's applied map version, the map's ingress/egress flags (`msg="map applied" … egress=on`), "the system resolves through the node" (the status has only the absence of `dns_not_protected`), `dial failed`, `link up` as an event, blob fetches and rejections, `listening on`, the local API's own "is down" error.
- **Tray (TP-086) mapping:** `status -json` is the local API's `Status` message as protojson writes it with the proto names, so a tray reading `GetStatus` and a script reading the CLI see the same field names and values; the only difference is `schema_version`, the CLI's in `-json` and the service's over the API. TP-048's kill-switch, allow-LAN and pause fields go into `Status` the same way and appear in `-json` with no CLI change (the package doc says so).
- TP-133 hasn't started (backlog on 2026-11-09), so there was nothing to merge first; its `agent` field follows the "JSON" convention.
## Log
- 2026-11-07 created in backlog
- 2026-11-07 split (owner's MVP cut): `status -json` stays; the network-reaching diag and the redacted report → TP-182
- 2026-11-09 backlog → in-progress, owner: agent-tp-168
- 2026-11-09 `status -json` in the one JSON convention (proto names, every field, byte-stable, `schema_version`), shared with `diag`; `DataPlane.interface`; `localapi.DialWith` for the no-network test; localapi doc "JSON", api-overview-reference `status`. Tests: `TestStatusJSONHasEveryFieldBySchemaName`, `TestStatusJSONSaysTheClientsSchema`, `TestStatusReachesOnlyTheLocalAPI`, `TestJSONIsByteStable`, and `TestTheCLIControlsTheNode` checks the served `schema_version`. Mutations, each caught: camelCase names (UseProtoNames off); zero values left out (EmitUnpopulated off); the client's schema_version not stamped; the service's not set; protojson's whitespace kept (caught by `TestJSONIsByteStable` only: protojson's randomization is off in the test binary, so the CLI-level comparison can't see it); `interface` not sent; `status` also calling Diagnose; `status` dialing tcp 192.0.2.1:53 through the CLI's dialer; the gRPC connection dialing tcp instead of the socket. `make lint`, `make test` pass
