---
id: TP-013
title: "Allow-ingress and allow-egress node settings"
milestone: M1
area: netmap
repo: thinkpol-vpn
size: M
depends_on: [TP-003, TP-010]
refs: [N8]
owner: agent-tp-013
branch: tp-013-ingress-egress
---

## Goal
Every server node has allow-ingress and allow-egress settings, both off by default; with ingress off the node is invisible to devices.

## Scope
- Fields in the map section; supported by the dev spec.
- Listener enforcement: with ingress off, device credentials are treated as unauthenticated (camouflage); only other nodes get in.
- The map builder never writes an ingress-off node's address into a device's section, and fails if a spec asks a device to connect to one.
- The egress flag is consumed by TP-014.

## Acceptance
- [x] in the lab, a device can't connect to an ingress-off node even when it knows the address — `lab/ingress_test.go` `TestIngressOffAdmitsOnlyServers`: device-b pings server-2 directly on map v1, then the space moves to v2 with server-2's ingress off (built by `dev map build`; device-b keeps v1, with server-2's address and a credential) and 5 of 5 of device-b's pings fail while device-a still reaches server-2 through server-1. The reader-side filter with a credential the server's section still lists (a map Build no longer makes) is tested in process: `TestIngressOffServesOnlyServers` (engines) and `TestServerWithIngressOffAcceptsNoDevice` (the supervisor's table); with the filter removed both fail, and in round 1 the lab variant failed with `AcceptsInbound` forced true
- [x] `map inspect` of a device section shows no address of an ingress-off node — in the lab test, `dev map inspect` of device-a's and device-b's sections of v2 shows server-1's address and not server-2's; `TestDevicesNeverSeeAnIngressOffServer` (devmap: every device section of the reference spec, where server-3 has ingress off and is device-a's peer through relays) and the goldens; `dev map build` refuses a spec that asks a device to dial one (unit tests, and in the lab test)

## Notes
- From TP-003: `netmap.InboundLink.PeerKind` tells the listener whether a peer is a device or a server, so an ingress-off node can treat device credentials as unauthenticated. Add `allow_ingress`/`allow_egress` to `NodeSettings` (schema, Go type, both conversions, Build policy, the test fixture).
- **From TP-010 (ingress off):** put the filter inside `dataplane.AcceptedInbound`. With ingress off, drop entries whose `netmap.InboundLink.PeerKind` is a device, so they become unauthenticated (camouflage). The engine and the supervisor then both apply it, so the two tables can't disagree.

- **Release note.** Maps built before TP-013 read `allow_ingress = false` and `allow_egress = false` for every server, so a node on this release refuses devices' links from such a map (they become unauthenticated). Rebuild maps with `ingress: true` on the servers devices dial before upgrading nodes (`lab/maps/m0.yaml` has it). Egress is only a setting until TP-014.
- **Done in TP-013 (2026-10-12, review round included):**
  - **Schema and type.** `NodeSettings.allow_ingress = 8`, `allow_egress = 9`; Go `NodeSettings.AllowIngress`, `AllowEgress` (both conversions, the netmap fixture: entries ingress on, the exit egress on). The rule is one method, `NodeSettings.AcceptsInbound(in)`: a server with ingress off accepts only `PeerKind == NodeServer` (unknown kinds refused too); devices have no ingress setting. `SectionReader` stays 1: no reader-2 marking (see D1). `Section.MinReader` is what `Open` read (for inspect); Build ignores it.
  - **Builder (`netmap.Build`).** `validate` (per section): devices can't set either setting, can't listen (no direct paths between devices yet: a device's listener would take links the ingress rules don't cover), and a server with ingress off lists no inbound link but servers'. `hiddenFromDevices` (across sections, recipients only): no link between a device and an ingress-off server whichever dials; every `InboundLink.PeerKind` is its peer's kind; no device endpoint has the IP of an ingress-off server (a concrete listener address of its own, or an address anyone dials it at), whatever id the link names (compared by IP, not port: the IP is what leaks). A shared node outside the map is checked by the builder of the map that has it (TP-040).
  - **Reader (defense in depth).** `dataplane.InboundFrom` (inside `AcceptedInbound`, the table the engine and the supervisor share) skips links `AcceptsInbound` refuses with `ReasonIngressOff` ("ingress off"), so a device's datagrams are Unknown at the supervisor and get the camouflage. `PathConfigFrom` doesn't count a refused device as adjacent either. No map Build makes needs it; it covers maps the node can't trust that far (TP-040's guest maps).
  - **devmap.** `ingress: true|false` and `egress: true|false` per server (default false, `${VAR}` allowed, devices refused, anything but true/false refused). A path whose device end neighbours a server with ingress off is refused at that hop ("server-2 has ingress off, so device-b can't connect to it"). Plan copies the settings. Inspect prints `ingress: on, egress: off` for servers (`egress: on (not enforced until TP-014)`), `min reader: N`, and marks an inbound link the node refuses `(refused: ingress off)`. `reference.yaml`: server-1 and server-2 ingress, server-3 hidden from devices with egress; `lab/maps/m0.yaml`: server-1 `ingress: true`; `lab/maps/ingress.yaml` for the lab test. Goldens updated.
  - **Agent.** `map applied` logs `ingress=on|off egress=off|"on (not enforced until TP-014)"` (the supervisor's line, and the engine's for a server's section). `supervisor.Space.Egress` stays zero: its `Uplink` is TP-014's to find.
  - **Docs.** PRD (Node, N8) and DESIGN ("Every server node relays", "Server agent") said an ingress-off node accepts "only other nodes"; devices are nodes too, so now "other servers". DESIGN says the builder writes no device link with such a node and none of its addresses into a device's section, and the node enforces the rule itself too.
  - **Tests.** netmap: Build refusals (device settings and listeners; a device dialing, accepting or dialed by an ingress-off server; a device's inbound link in its section; a spoofed peer kind either way; its address under another id, dialed or listened on), `TestIngressOffAcceptsOnlyServers` (the rule, reader 1, settings round-trip). dataplane: `TestAcceptedInboundHonoursIngress`, `TestIngressOffServesOnlyServers` (engines in process: a device with a working credential refused, a server relaying in, ingress on lets the device in). devmap: spec errors with positions, `TestDevicesNeverSeeAnIngressOffServer`, `TestInspectMarksRefusedLinks`, goldens. agent: `TestServerWithIngressOffAcceptsNoDevice` (the supervisor's table from a section with ingress off). The supervisor's lab-only `handMadeSpace` section allows ingress (its dialers are devices). Lab: `TestIngressOffAdmitsOnlyServers`.
  - **Lab finding.** In server mode a worker can't dial another server yet (the supervisor's forward drop; TP-014's decided accept for dials to the section's own endpoints). The lab test runs the dialing server-1 with `-mode device` until then; server-2, the ingress-off node under test, runs in server mode (supervisor and worker).
- **For TP-014 (egress):** the setting is `section.Node.AllowEgress`: in `serverSpaces.apply` (`internal/agent/node.go`, fill `supervisor.Space.Egress`) and in the worker's section (`runner.section`) for the worker's SNAT. Drop "(not enforced until TP-014)" from `serverSettings` (agent) and `DescribeSection` (devmap). When TP-014 lands, the lab test's server-1 can run in server mode.
- **For TP-030 (chains, N9):** first hop `AllowIngress`, last hop `AllowEgress`, every member of a hop group too; Build's cross-section check sits next to `hiddenFromDevices` in `envelope.go`, devmap's next to the ingress check in `checker.paths`.
- **For TP-040 (grants):** a guest space's inbound table comes from the guest's map, whose own `AllowIngress` must not be trusted: before `AcceptedInbound`, set the guest section's `AllowIngress` (and egress) to what the owner's map grants (at most what the node allows). `hiddenFromDevices` checks recipients only, so the guest's builder must apply the grant to its devices' links to the shared node.
- **For TP-034/TP-035 (controller):** turning a server's ingress off = the setting plus removing every link between it and devices from both sides: devices' links and the server's inbound links (Build refuses either; the server keeps no device secrets it doesn't need). The node filters too, but a map must never rely on it: a node on an older reader keeps admitting what it was told to.
- **For TP-038 (`node add`):** a new node starts with both off, the zero value; `node set --ingress` is the controller flipping the setting as above.

## Review findings
Review 2026-10-12: node-side enforcement holds; the builder needs fixing. Decided by the orchestrator.

- [x] F1 Build refuses, in both directions, any link between a device and an ingress-off server (a server's links to device recipients; a device's inbound links from ingress-off servers); an `InboundLink.PeerKind` that disagrees with the named recipient's kind; a device endpoint address equal to any concrete listener address, or any endpoint address used elsewhere, of an ingress-off server. `validate` refuses device listeners until direct paths exist (documented). Tests: (a) a server dials a device, (b) a spoofed PeerKind, (c) an ingress-off server's address under another id
- [x] D1 (changes decision 1 of the first round) Build also refuses devices' inbound links in an ingress-off server's own section (the builder omits them; devmap never emits them), so no reader-2 marking for ingress: removed. `AcceptsInbound` stays on the reader side as defense in depth and for TP-040's guest maps. Why: a v0.1.0 node refusing a reader-2 section keeps its last map, keeps admitting the devices and stops taking later maps (revocations included), which fails open; and it would keep device secrets on a node that doesn't need them. Note for TP-034/035 accordingly
- [x] F2 Fix the `devicesReachOnlyIngress` doc comment
- [x] Nits: release note in the ticket (maps built before TP-013 read `allow_ingress = false`); inspect marks refused device links (if any remain) and prints the section's min_reader; "egress (not enforced until TP-014)" in inspect and in the applied log line
- [x] Downstream notes copied into TP-014, TP-030, TP-034, TP-035, TP-038, TP-040 (TP-040: a guest map's ingress replaced by what the owner's grant allows), one Log line each

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): notes on inbound peer kinds and adding the settings
- 2026-10-11 docs (TP-010 review): notes from the shared listener
- 2026-10-12 backlog → in-progress — owner: agent-tp-013, branch: tp-013-ingress-egress
- 2026-10-12 implemented: schema fields, Build rules, the ingress filter in `InboundFrom`/`PathConfigFrom`, section reader 2, devmap `ingress`/`egress`, agent logs, lab test; PRD (Node, N8) and DESIGN wording "other nodes" → "other servers", DESIGN notes the node enforces ingress from its own section
- 2026-10-12 in-progress → review — all acceptance checked; `make lint`, `make test`, `go test -race` on netmap, dataplane, devmap, agent and cmd/thinkpol, `make lab-test` (incl. `TestIngressOffAdmitsOnlyServers`) pass
- 2026-10-12 review → has-errors — review: F1, D1, F2, nits, downstream notes (see Review findings)
- 2026-10-12 has-errors → in-progress — owner: agent-tp-013, picking up the review findings
