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
- [x] `make lint`, `make test`, `make lab-test` pass

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
  - Enum values are lower snake_case without their type's prefix (`connected`, `ok`, `device`, the zero value `unspecified`), as the text view spells them: the naming verdict (api-overview.md "Verdicts", "enumerated values are snake_case everywhere") wins over F3's "keep protojson's enum spelling" (orchestrator's decision, 2026-11-09). writeJSON does it once for every enum field the schema has, nested, in a list or as a map's value, guided by the descriptor (a string field holding an enum's name stays as it is) and keeping the fields' order. 64-bit integers stay strings. diag's `status` changed spelling, so `SchemaVersion` is 2 (the doc says why).
  - "No network call": `localapi.DialWith(path, Dialer)` opens every connection the client makes, the probe and gRPC's, through one dialer; the CLI's `env.dial` sets it. The test's dialer lets through only `unix <socket>` and fails anything else, and the fake node fails the test if `status` asks for anything but the status (`Diagnose` reads the host). What it can't see: code that calls `net.Dial` around the dialer.
- **What TP-200 can read from `status -json` instead of logs** (skimmed lab/*_test.go): mode (`mode`; the lab greps `mode=device`); `mode_mismatch`, `no_link_up`, `neighbor_down`, `exit_no_handshake`, `dns_not_protected`, `dns_upstream_refused` and every other problem code (`health.level`, `health.problems`); connected or not (`connection`); links and their state (`data_plane.neighbors[].up`, `.links[].transport/dialed/active/up`); handshakes (`data_plane.peers[].last_handshake`); the map version followed and whether its Apply failed (`map_version`, `data_plane.last_apply_error`); the overlay MTU (`data_plane.mtu`; lab/settings_test.go greps the text); the TUN (`data_plane.interface`); counters (`data_plane.counters`; lab/routetable_test.go already reads them); rule preset (`rule_preset`, `rules_enforced`, `rule_preset_unavailable`); toggles (`connect_on_boot`); a server's workers, uplink (`uplink.ipv4/ipv6/forwarding4/forwarding6`, the lab greps `egress_ipv4=on`) and public listeners. Not in the status, so still log lines or a new field: a server worker's applied map version, the map's ingress/egress flags (`msg="map applied" … egress=on`), "the system resolves through the node" (the status has only the absence of `dns_not_protected`), `dial failed`, `link up` as an event, blob fetches and rejections, `listening on`, the local API's own "is down" error.
- **Tray (TP-086) mapping:** `status -json` is the local API's `Status` message as protojson writes it with the proto names, so a tray reading `GetStatus` and a script reading the CLI see the same field names and values; the only difference is `schema_version`, the CLI's in `-json` and the service's over the API. TP-048's kill-switch, allow-LAN and pause fields go into `Status` the same way and appear in `-json` with no CLI change (the package doc says so).
- TP-133 hasn't started (backlog on 2026-11-09), so there was nothing to merge first; its `agent` field follows the "JSON" convention.
## Review findings
- [ ] R1.1 version skew: an enum number missing from the CLI's descriptor is written as a bare JSON number; write "unknown" (not google.protobuf.NullValue). Test: dynamicpb enum number not in the descriptor.
- [ ] R1.2 the JSON's `schema_version` is the CLI's for every document (status and diag), stamped after the enum pass; `Status.schema_version` (field 19) removed; one exported `WriteJSON`; the older-service gap documented.
- [ ] R1.3 enumPrefix taken from the zero value's name (`…_UNSPECIFIED`), not a CamelCase split (wrong for IPv6State/DNSState). Test with an acronym-named enum.
- [ ] R1.4 the text view's enum names derived from the same function as the JSON's (unknown → "unknown"), byte-identical for today's values; test over every value of the three enums.
- [ ] R1.5 drop DialWith/Dialer/env.dial; an internal/agent test that `Status()` makes no network and no host call; acceptance box reworded to what is proven.
- [ ] R1.6 duration examples in doc.go and api-overview-reference.md as protojson writes them (0/3/6/9 fractional digits), with the rule.
- [ ] R1.7 `status -watch -json` prints one compact object per line (NDJSON); doc and test.
- [ ] R1.8 nits: nil status guard; error string; test name; cli.go env comment; MkdirTemp comment; convert.go dataPlaneProto takes the interface; drop the constant check and the CLI byte-equality check; Notes on version 2 and tray/CLI spelling; a comment on why the ordered JSON codec stays.
## Log
- 2026-11-07 created in backlog
- 2026-11-07 split (owner's MVP cut): `status -json` stays; the network-reaching diag and the redacted report → TP-182
- 2026-11-09 backlog → in-progress, owner: agent-tp-168
- 2026-11-09 `status -json` in the one JSON convention (proto names, every field, byte-stable, `schema_version`), shared with `diag`; `DataPlane.interface`; `localapi.DialWith` for the no-network test; localapi doc "JSON", api-overview-reference `status`. Tests: `TestStatusJSONHasEveryFieldBySchemaName`, `TestStatusJSONSaysTheClientsSchema`, `TestStatusReachesOnlyTheLocalAPI`, `TestJSONIsByteStable`, and `TestTheCLIControlsTheNode` checks the served `schema_version`. Mutations, each caught: camelCase names (UseProtoNames off); zero values left out (EmitUnpopulated off); the client's schema_version not stamped; the service's not set; protojson's whitespace kept (caught by `TestJSONIsByteStable` only: protojson's randomization is off in the test binary, so the CLI-level comparison can't see it); `interface` not sent; `status` also calling Diagnose; `status` dialing tcp 192.0.2.1:53 through the CLI's dialer; the gRPC connection dialing tcp instead of the socket. `make lint`, `make test` pass
- 2026-11-09 merged origin/rewrite (TP-025); `make lint`, `make test` pass on the merge. Full `make lab-test` on c365474: the node phase passes (37 packages) and every lab test but one passes, among them the ones reading `status` and `status -json` (localapi's JSON regex, route table counters, settings' MTU line, health, DNS, egress). The one failure, `TestHealthWithAnExitThatNeverHandshakes`, is on rewrite already and not this branch's: TP-195's test starts server-1 and server-2 with a plain `thinkpol up` and not `upFor`, so since TP-111 they run in device mode ("the map makes this node a server, but it runs in device mode" in both servers' logs), nothing answers and the device reports `no_link_up`. The fix is one line in lab/health_test.go (`n.Start(t, upFor(name, "-egress-allowed", servers)...)`), but lab/ is outside this ticket's files, so the lab box stays unchecked
- 2026-11-09 handoff: code, tests, docs done; waiting on the lab test fix above (a lab/ owner's, or permission to make it here), then one full `make lab-test` and in-progress → review
- 2026-11-09 enum values in lower snake_case without their prefix in writeJSON (status -json and diag), `SchemaVersion` 2; localapi doc "JSON", api-overview-reference (status -json, diag, `Status`, `Diagnostics`). Readers of the old spelling updated: lab/localapi_test.go (`"connection": "connected"`), lab/diag_test.go (`schema_version` 2, `connected`); nothing else on rewrite parses them (no device-kit doc names them). Tests: `TestJSONSpellsEnumsAsTheTextDoes` (status -json, diag's status, nested health.level, unset → `unspecified`, a string field holding `CONNECTION_CONNECTED` untouched), `TestJSONSpellsEveryEnumFieldInTheSchema` (a dynamic schema: repeated enum, map<string, enum>, enum in a repeated nested message, field order), `TestEnumValueName`. Mutations, each caught: the enum pass skipped (both tests); no recursion into messages (health.level, diag's status, the nested list); list elements not rewritten. `make lint`, `make test` pass
- 2026-11-09 merged origin/rewrite (the lab fix "lab: TP-195's health test starts its servers in server mode"); `make lint`, `make test` pass on eaa1148. Full `make lab-test` on eaa1148 passes: the lab phase (lab ok in 214 s, among them TestHealthWithAnExitThatNeverHandshakes, the localapi JSON regex and diag's schema 2 / `connected`) and the node phase (37 packages). Not verified: macOS (`status -json` on a Mac runs only in `make test`'s fakes)
- 2026-11-09 in-progress → review
- 2026-11-09 review → has-errors (round 1 findings R1.x)
