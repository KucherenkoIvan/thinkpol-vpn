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
An exit lets its spaces reach any destination by default. What it refuses is the operator's choice, made with classic blocklists of domain names and IP subnets.

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
- **Blocklists are classic lists of domain names and IP subnets (owner, 2026-10-23).**
  - **Format:** a plain text file, one entry per line, `#` comments.
    - An entry is a domain (`example.com` blocks the name and its subdomains), an IP address, or a subnet in CIDR (`10.0.0.0/8`, `fd00::/8`).
    - Several files may be given. Name what happens to an entry the parser can't read: refused at load, with the file and line.
  - **Where:**
    - **Per exit (node owner):** `-egress-blocklist` names one or more files (flag, env var). A reload (SIGHUP) re-reads them without restarting workers.
    - **Per space (in its map):** decide whether a space may carry its own list, and whether the node owner's list always wins. Write the rule down.
  - **Enforcement:**
    - IP addresses and subnets in each space's namespace and again in the root, as today; refused the same way and counted.
    - Domains at the exit's resolver for the space: a blocked name gets a refusal, not an address. Its addresses are also refused while the resolver remembers them (the answers it gave for a blocked name don't reach the space). A client that resolves elsewhere (its own DoH, a hard-coded IP) gets past a domain entry; only IP entries stop that. Say so in the docs.
  - **Example lists in the repo** (not defaults): `private.txt` (RFC 1918, 100.64/10, ULA, link-local) and `metadata.txt`.
    - `metadata.txt` holds AWS/GCP 169.254.169.254 and `fd00:ec2::254`, Azure 168.63.129.16, Alibaba 100.100.100.200, and the metadata names (`metadata.google.internal`, …).
    - TP-112's refusal hint (`EgressNotWorthAllowing`) uses the same metadata list.
- **`-egress-allowed` goes away**, since nothing is blocked by default to except from.
- **Visibility:**
  - The exit's status says which lists apply and how many entries each has.
  - At start, an exit on a cloud VM whose metadata service is reachable and not blocked says so once: a warning in the log, not a refusal.
- **Docs:**
  - docs/design/server-agent.md (the egress bullet: "never the destinations no space should reach" changes);
  - the supervisor package doc;
  - docs/runbook-pre-controller.md, which shows how to block private networks and metadata on a cloud exit;
  - a RESIDUAL-RISKS.md row: by default a member can reach the provider's private network and metadata service, decided, with the reason.
- **Future:** named blocklists shared through the map, and domain blocklists through the rules' lists. Out of scope here; note them in the design file.

## Acceptance
- [ ] with no blocklist, a space reaches a private address and the metadata address in the lab, and still can't reach loopback or multicast through the uplink
- [ ] a blocklist file with a subnet, an address and a domain refuses exactly those: the IPs in the namespace and in the root, the domain at the exit's resolver (lab); a reload changes the list without restarting workers; an unreadable line is refused at load, naming the file and line
- [ ] the metadata warning fires on start when the metadata address is reachable and not blocked (unit test with a fake probe)
- [ ] docs and the residual row as above
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-112's round-2 reviews (2026-10-21).

## Log
- 2026-10-21 created in backlog (TP-112 review round 2)
- 2026-10-23 docs: rescoped to the owner's decision: nothing blocked by default, configurable blocklists (presets and arbitrary prefixes); renamed
- 2026-10-23 docs: the owner wants classic blocklists (domain names and IP subnets in list files), not presets; example lists instead of presets; domain entries enforced at the exit's resolver
