---
id: TP-067
title: "Resource footprint and system requirements"
milestone: M1
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-012]
refs: [PRD#performance, DESIGN#processes]
needs_human: ""
owner: ""
branch: ""
---

## Goal
Measure what thinkpol needs to run, so that README can state minimal and recommended system requirements for nodes and clients. Today these are estimates only.

## Scope
- A lab test or `make` target that runs a 2-hop chain (device → relay → exit) with each node container limited to 1 vCPU and 512 MB. It records:
  - RSS and CPU for the supervisor and for each worker
  - RSS and CPU for the device process
  - end-to-end throughput through WireGuard plus the udp transport (iperf3 or similar)
  - per-hop added latency
  - the full ~23k-prefix route install time
- Run it once more with 3 spaces on one node.
- Record the results in Notes.
- Add a "System requirements" section to README.md with minimal and recommended values. Mark each value as measured or estimated.
- Optional: set default worker MemoryMax/PidsMax values from the measurements.

## Out of scope
- Tuning the data plane to improve the numbers: this ticket measures, it doesn't optimize.
- Measuring on any real host: measurements run in lab containers only.

## Acceptance
- [ ] the lab measurement is reproducible with a single command
- [ ] README has the system requirements, backed by the numbers in Notes

## Notes
- **From the 2026-10-14 estimate:** the hard requirements known from code are: node: Linux with kernel 4.17 or newer (5.7 or newer for the cgroup fd), /dev/net/tun, nftables with conntrack, namespaces, root, cgroup v2 recommended, and a KVM VPS rather than OpenVZ/LXC; client: macOS on Apple silicon, or Linux 4.17 or newer, with outbound UDP. The PRD target is at least 50 Mbit/s over two hops on 1-vCPU nodes. The first device test's exit ran within a 0.75 CPU / 300 MB container limit. Nothing has been measured yet.

## Log
- 2026-10-14 created in backlog
