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
- [x] in the lab, a device can't connect to an ingress-off node even when it knows the address — `lab/ingress_test.go` `TestIngressOffAdmitsOnlyServers`: device-b pings server-2 directly on map v1 (credential valid), then server-2's ingress goes off (v2: same secrets, server-2's section still lists device-b's inbound link, device-b keeps v1) and 5 of 5 pings fail while device-a still reaches server-2 through server-1; server-2's worker logs `inbound link …: ingress off`. With `AcceptsInbound` forced true the test fails ("device-b reached server-2 with its ingress off").
- [x] `map inspect` of a device section shows no address of an ingress-off node — `TestDevicesNeverSeeAnIngressOffServer` (devmap: inspect output of every device section of the reference spec, where server-3 has ingress off and is device-a's peer through relays) and the goldens; `dev map build` refuses a spec that asks a device to dial one (unit tests, and in the lab test)

## Notes
- From TP-003: `netmap.InboundLink.PeerKind` tells the listener whether a peer is a device or a server, so an ingress-off node can treat device credentials as unauthenticated. Add `allow_ingress`/`allow_egress` to `NodeSettings` (schema, Go type, both conversions, Build policy, the test fixture).
- **From TP-010 (ingress off):** put the filter inside `dataplane.AcceptedInbound`. With ingress off, drop entries whose `netmap.InboundLink.PeerKind` is a device, so they become unauthenticated (camouflage). The engine and the supervisor then both apply it, so the two tables can't disagree.

- **Done in TP-013 (2026-10-12):**
  - **Schema and type.** `NodeSettings.allow_ingress = 8`, `allow_egress = 9`; Go `NodeSettings.AllowIngress`, `AllowEgress` (both conversions, the netmap fixture: entries ingress on, the exit egress on). The rule is one method, `NodeSettings.AcceptsInbound(in)`: a server with ingress off accepts only `PeerKind == NodeServer` (unknown kinds refused too); devices have no ingress setting.
  - **Builder (`netmap.Build`).** A device section with either setting is refused. Across sections (`devicesReachOnlyIngress`): a device's link to a recipient server with ingress off is refused, so no device's section has its address (first hops are adjacent nodes, so paths follow). Only recipients can be checked: a shared node outside the map is the guest builder's to check (TP-040). Build does **not** refuse devices' inbound links in an ingress-off server's section: the node enforces ingress itself, so a controller can flip the setting without touching the server's links. Such a section is marked `min_reader = 2` (`SectionReader` is now 2), so a reader-1 node (v0.1.0) refuses that section rather than accepting the devices; every other section stays reader 1 and v0.1.0 nodes keep reading them.
  - **Reader.** `dataplane.InboundFrom` (inside `AcceptedInbound`, the table the engine and the supervisor share) skips links `AcceptsInbound` refuses with `ReasonIngressOff` ("ingress off"), so a device's datagrams are Unknown at the supervisor and get the camouflage. `PathConfigFrom` doesn't count a refused device as adjacent either (first and next hops through it are skipped as not adjacent), so the two halves can't disagree. Put the filter in `InboundFrom` rather than after it so nothing that builds an inbound table can skip it.
  - **devmap.** `ingress: true|false` and `egress: true|false` per server (default false, `${VAR}` allowed, devices refused, anything but true/false refused). A path whose device end neighbours a server with ingress off is refused at that hop ("server-2 has ingress off, so device-b can't connect to it"). Plan copies the settings; inspect prints `ingress: on, egress: off` for servers. `reference.yaml`: server-1 and server-2 ingress, server-3 hidden from devices with egress; `lab/maps/m0.yaml`: server-1 `ingress: true`. Goldens updated (only the settings lines changed).
  - **Agent.** `map applied` logs `ingress=… egress=…` (the supervisor's line, and the engine's for a server's section). `supervisor.Space.Egress` stays zero: its `Uplink` is TP-014's to find, so nothing here pretends egress works.
  - **Docs.** PRD (Node, N8) and DESIGN ("Every server node relays", "Server agent") said an ingress-off node accepts "only other nodes"; devices are nodes too, so now "other servers". DESIGN says the node enforces it from its own section and that such a section needs reader 2.
  - **Tests.** netmap: Build refusals (device settings, a device linking to an ingress-off server), `TestIngressOffAcceptsOnlyServers` (the rule, reader 2 only on the section that needs it, settings round-trip). dataplane: `TestAcceptedInboundHonoursIngress`, `TestIngressOffServesOnlyServers` (engines in process: a device with a working credential refused, a server relaying in, ingress on lets the device in). devmap: spec errors with positions, `TestDevicesNeverSeeAnIngressOffServer`, goldens. agent: `TestServerWithIngressOffAcceptsNoDevice` (the supervisor's table). The supervisor's lab-only `handMadeSpace` section now allows ingress (its dialers are devices). Mutations checked: the filter off in `InboundFrom` fails the unit tests; `AcceptsInbound` forced true fails the lab test.
  - **Lab finding.** In server mode a worker can't dial another server yet (the supervisor's forward drop; TP-014's decided accept for dials to the section's own endpoints). The lab test runs the dialing server-1 with `-mode device` until then; server-2, the ingress-off node under test, runs in server mode (supervisor and worker).
- **For TP-014 (egress):** the setting is `section.Node.AllowEgress`: in `serverSpaces.apply` (`internal/agent/node.go`, fill `supervisor.Space.Egress`) and in the worker's section (`runner.section`) for the worker's SNAT. When TP-014 lands, the lab test's server-1 can run in server mode.
- **For TP-030 (chains, N9):** first hop `AllowIngress`, last hop `AllowEgress`, every member of a hop group too; Build's cross-section check sits next to `devicesReachOnlyIngress` in `envelope.go`, and devmap's next to the ingress check in `checker.paths`.
- **For TP-040 (grants):** a guest space's inbound table comes from the guest's map, whose own `AllowIngress` must not be trusted: before `AcceptedInbound`, set the guest section's `AllowIngress` (and egress) to what the owner's map grants (at most what the node allows).
- **For TP-034/TP-035 (controller):** turning ingress off = the setting plus dropping devices' links to the node from device sections (Build refuses otherwise); the server's section may keep the devices' inbound links (reader 2). `node add` (TP-038) starts with both off: the zero value.

## Review findings
Review 2026-10-12: node-side enforcement holds; the builder needs fixing. Decided by the orchestrator.

- [ ] F1 Build refuses, in both directions, any link between a device and an ingress-off server (a server's links to device recipients; a device's inbound links from ingress-off servers); an `InboundLink.PeerKind` that disagrees with the named recipient's kind; a device endpoint address equal to any concrete listener address, or any endpoint address used elsewhere, of an ingress-off server. `validate` refuses device listeners until direct paths exist (documented). Tests: (a) a server dials a device, (b) a spoofed PeerKind, (c) an ingress-off server's address under another id
- [ ] D1 (changes decision 1 of the first round) Build also refuses devices' inbound links in an ingress-off server's own section (the builder omits them; devmap never emits them), so no reader-2 marking for ingress: removed. `AcceptsInbound` stays on the reader side as defense in depth and for TP-040's guest maps. Why: a v0.1.0 node refusing a reader-2 section keeps its last map, keeps admitting the devices and stops taking later maps (revocations included), which fails open; and it would keep device secrets on a node that doesn't need them. Note for TP-034/035 accordingly
- [ ] F2 Fix the `devicesReachOnlyIngress` doc comment
- [ ] Nits: release note in the ticket (maps built before TP-013 read `allow_ingress = false`); inspect marks refused device links (if any remain) and prints the section's min_reader; "egress (not enforced until TP-014)" in inspect and in the applied log line
- [ ] Downstream notes copied into TP-014, TP-030, TP-034, TP-035, TP-038, TP-040 (TP-040: a guest map's ingress replaced by what the owner's grant allows), one Log line each

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): notes on inbound peer kinds and adding the settings
- 2026-10-11 docs (TP-010 review): notes from the shared listener
- 2026-10-12 backlog → in-progress — owner: agent-tp-013, branch: tp-013-ingress-egress
- 2026-10-12 implemented: schema fields, Build rules, the ingress filter in `InboundFrom`/`PathConfigFrom`, section reader 2, devmap `ingress`/`egress`, agent logs, lab test; PRD (Node, N8) and DESIGN wording "other nodes" → "other servers", DESIGN notes the node enforces ingress from its own section
- 2026-10-12 in-progress → review — all acceptance checked; `make lint`, `make test`, `go test -race` on netmap, dataplane, devmap, agent and cmd/thinkpol, `make lab-test` (incl. `TestIngressOffAdmitsOnlyServers`) pass
- 2026-10-12 review → has-errors — review: F1, D1, F2, nits, downstream notes (see Review findings)
