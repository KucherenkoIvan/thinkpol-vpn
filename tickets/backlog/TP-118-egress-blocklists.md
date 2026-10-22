---
id: TP-118
title: "Exit egress: nothing blocked by default; configurable blocklists"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-112]
refs: [docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
An exit lets its spaces reach any destination by default. What it refuses is the operator's choice, made with blocklists that are easy to set: named presets (private networks, cloud metadata services) and arbitrary prefixes.

## Scope
- **Owner's decision (2026-10-23):** don't block anything by default; give easy-to-configure blocklists, not only for private networks but for arbitrary destinations too.
- **Remove the policy part of today's defaults.** Today `supervisor.egressBlocked` refuses these unless `-egress-allowed` names them:
  - the private networks (RFC 1918, shared address space 100.64/10, ULA);
  - link-local;
  - the cloud metadata services.
- **Keep only what can never be a destination through the uplink:**
  - unspecified, loopback (0/8, 127/8, ::/127);
  - multicast;
  - IPv4-mapped (::ffff:0:0/96);
  - zoned addresses.
  - Say why: these are about routing, not policy.
- **Blocklists:**
  - **Per exit (node owner):** `-egress-block` takes a list of prefixes and presets (`private`, `metadata`, `link-local`), as a flag, an env var or a file. Changes apply on reload (SIGHUP) without restarting workers.
  - **Per space (in its map):** decide whether a space may narrow its own egress further, and whether the node owner's list always wins. Write the rule down.
  - **Enforcement as today:** in each space's namespace and again in the root. A blocked destination is refused the same way and counted.
- **The presets are named lists in one place.** `metadata` holds AWS/GCP 169.254.169.254, `fd00:ec2::254`, Azure 168.63.129.16 and Alibaba 100.100.100.200. TP-112's refusal hint (`EgressNotWorthAllowing`) uses the same list.
- **`-egress-allowed` goes away,** since nothing is blocked to except from. If a blocklist needs exceptions, say how they're written.
- **Visibility:**
  - The exit's status says which blocklists apply.
  - At start, an exit on a cloud VM whose metadata service is reachable and not blocked says so once: a warning in the log, not a refusal.
- **Docs:**
  - docs/design/server-agent.md (the egress bullet: "never the destinations no space should reach" changes);
  - the supervisor package doc;
  - docs/runbook-pre-controller.md, which shows how to block private networks and metadata on a cloud exit;
  - a RESIDUAL-RISKS.md row: by default a member can reach the provider's private network and metadata service, decided, with the reason.
- **Future:** named blocklists shared through the map, and domain blocklists through the rules' lists. Out of scope here; note them in the design file.

## Acceptance
- [ ] with no blocklist, a space reaches a private address and the metadata address in the lab, and still can't reach loopback or multicast through the uplink
- [ ] `-egress-block private,metadata,203.0.113.0/24` refuses exactly those, in the namespace and in the root (lab), and a reload changes the list without restarting workers
- [ ] the metadata warning fires on start when the metadata address is reachable and not blocked (unit test with a fake probe)
- [ ] docs and the residual row as above
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-112's round-2 reviews (2026-10-21).

## Log
- 2026-10-21 created in backlog (TP-112 review round 2)
- 2026-10-23 docs: rescoped to the owner's decision: nothing blocked by default, configurable blocklists (presets and arbitrary prefixes); renamed
