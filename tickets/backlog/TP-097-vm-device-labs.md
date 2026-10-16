---
id: TP-097
title: "VM device labs for macOS and Windows"
milestone: M2
area: lab
repo: thinkpol-vpn
size: L
depends_on: []
refs: [DESIGN#lab]
owner: ""
branch: ""
---

## Goal
Device checks that need a real macOS or Windows network stack run in throwaway virtual machines on the development Mac. Agents drive them over SSH and may run anything there as administrator, because breaking a VM costs nothing. The owner's own computers get only the short final checklist. A router VM gives the VMs native IPv6, so device steps that need an IPv6 network (TP-096) can run without one.

## Scope
- Pick the VM tool: Tart, UTM or another, by research. Criteria:
  - headless and scriptable;
  - snapshots and restore;
  - macOS guests and Windows 11 ARM guests;
  - licence terms (Apple allows two macOS VMs per Mac);
  - networking modes;
  - resources: the development Mac has 16 GB of RAM, so one guest at a time next to Docker.
- A macOS guest image and a Windows 11 ARM guest image, each reset to a clean snapshot before a run.
- A private network between the guests and a small Linux router VM (or container) that gives them IPv4 and native IPv6. It has to support a Wi-Fi-like network change (switching the guest's network) and an "other VPN" case.
- `make` targets in the style of the lab: start a guest from its snapshot, copy a build in, run a check script over SSH, collect the evidence (`thinkpol diag` from TP-091, captures, logs), stop and reset.
- What VMs can't reproduce stays on the owner's checklist: real sleep and wake, Wi-Fi radio changes, prompts that need the GUI.

## Out of scope
- CI. There is none; the agents run this.
- The development Mac's own network: the VM tool's virtual interfaces are the only host-side change. The owner approved them on 2026-10-16. Agents never change the host's routes, DNS or firewall.

## Acceptance
- [ ] research notes with the tool choice and why, in Notes
- [ ] a macOS guest runs TP-078's pf guard checks (steps 0-10) with native IPv6 from the router, and the evidence is collected without touching the host
- [ ] a Windows guest boots from its snapshot and runs a smoke script over SSH (it is ready for TP-047)
- [ ] reset to a clean snapshot after a run is verified, and leaves nothing on the host but the VM tool's own files

## Notes
- **Origin.** Device tests took the owner's time on their daily Mac, and a network without IPv6 left TP-078's leak paths unproven (TP-096). See ORCHESTRATION.md, "Device testing (2026-10-16)".

## Log
- 2026-10-16 created in backlog (owner approved VM device labs)
