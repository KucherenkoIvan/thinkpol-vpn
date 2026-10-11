---
id: TP-038
title: "Provisioning over SSH"
milestone: M4
area: features/provisioning
repo: thinkpol-vpn
size: L
depends_on: [TP-034]
refs: [A4, S2]
owner: ""
branch: ""
---

## Goal
`thinkpol node add root@host` turns a fresh Linux box into a node, and re-running it repairs the node.

## Scope
- Idempotent steps: upload the binary, systemd unit, sysctls, base nftables, volatile journald, state dir permissions, key generation on the node, public key retrieval, add to the space with ingress and egress off, publish.
- `thinkpol node set <node> --ingress --egress`.
- A dry-run mode printing the plan.

## Acceptance
- [ ] a fresh lab container becomes a working node with one command; running it again changes nothing

## Notes
- **Shaping rollout (TP-027):** the controller puts shaping, or a new shaping field or value, into a link only when both ends' nodes reported supporting it (DESIGN "Transports own traffic shape"). Provisioning registers the node with its agent version and capabilities, so the first map it gets carries only shaping it supports.
- **From TP-011's review (deferred here):**
  - **A shared key-file codec.** `internal/devmap/keys.go` (writes and reads dev key files, YAML with positions) and `internal/agent/keyfile.go` (reads `node.key`/`space.pub`) duplicate the format. Extract `internal/keyfile`: read and write, the 0600 rule for private files (written with explicit chmod, refused on read when others can read them), owner checks, redacted `String`s; used by devmap and agent (depguard: no devmap dependency for the agent).
  - **node.key written on the node.** Provisioning has the node generate its own keys (`netmap.GenerateNodeKey`, `GenerateWireGuardKey`, a random node id) and write `/var/lib/thinkpol/node.key` once, 0600, owned by the agent's user, in a 0700 directory no one else can write (`thinkpol up` refuses anything looser, `internal/agent/state.go`), then report only the public half. `space.pub` comes from the invite/controller.
  - **First boot without a map:** see TP-037's Notes; until the first map arrives, `thinkpol up` refuses to start.
- **From TP-013:** a new node starts with ingress and egress off, the zero value of `NodeSettings.AllowIngress`/`AllowEgress`; `node set --ingress` is the controller flipping the setting and removing or adding the devices' links accordingly (TP-034's notes).

## Log
- 2026-10-10 created in backlog
- 2026-10-11 docs (TP-011 review): notes on a shared key-file codec, node.key written on the node, first boot
- 2026-10-12 docs (TP-013 review): notes from the ingress and egress settings
