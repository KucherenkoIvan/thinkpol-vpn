---
id: TP-206
title: "Linux: a netdev egress chain so layer-2-bridged traffic meets the kill switch"
milestone: M3
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-048]
refs: [D4, R2, RR61]
owner: ""
branch: ""
---

## Goal
On Linux, traffic bridged at layer 2 onto the uplink (Docker's macvlan and ipvlan networks, libvirt's macvtap, a bridge enslaving eth0 without br_netfilter) meets the kill switch: today it never reaches the inet output and forward hooks and leaves direct whatever the kill switch says (RR61).

## Scope
- A netdev-family egress chain on each physical uplink interface (kernel 5.16+; say what older kernels get), or a bridge-family chain, holding the kill switch's allow and direct sets and its DNS refusals for frames not sent by the host's own stack.
- Kept on interfaces that appear and go (the watch from TP-209, or the re-apply).
- docs: firewall doc.go, security.md, RR61 narrowed.

## Out of scope
- macOS (pf sees bridged VM traffic differently; device check 12a in TP-048).
- Exempting DHCP and neighbour discovery for VMs bridged onto the uplink (RR61 says they get neither without allow-LAN): decide in this ticket whether the egress chain changes that.

## Acceptance
- [ ] lab: a macvlan namespace on the uplink, the kill switch on and down: its pings to foreign4/foreign6 refused, an entry answering (lab test, mutation-checked)
- [ ] lab: a bridge enslaving the uplink without br_netfilter, a VM-side namespace on it: the same (lab test)
- [ ] the host's own traffic and the links' marked sockets unaffected (the existing kill-switch lab tests still pass)

## Notes
- Egress hooks in the netdev family need Linux 5.16+; the lab kernel's version decides what can be tested.
- From TP-048's review rounds 2 and 3 (R2.6, RR61).

## Log
- 2026-11-12 created in backlog (from TP-048's review)
