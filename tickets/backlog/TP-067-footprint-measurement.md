---
id: TP-067
title: "Resource footprint and system requirements"
milestone: M1
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-012]
refs: [PRD#performance, DESIGN#processes]
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
- Set default worker `MemoryMax`, `PidsMax` and `FairShare` from the measurements (wire them through `supervisor.Options` from `node.go`).

## Out of scope
- Tuning the data plane to improve the numbers: this ticket measures, it doesn't optimize.
- Measuring on any real host: measurements run in lab containers only.

## Acceptance
- [ ] the lab measurement is reproducible with a single command
- [ ] README has the system requirements, backed by the numbers in Notes
- [ ] production builds set non-zero `MemoryMax`, `PidsMax` and `FairShare` defaults from the measurements

## Notes
- **Independent review (2026-10-15):** without cgroup limits a compromised worker can fork-bomb the host; the unmetered reply path (`shared.go:652-656`, a blocking `WriteToUDPAddrPort` on the shared socket) lets one flooding worker stall every space's replies.
- **From the 2026-10-14 estimate:** the hard requirements known from code are: node: Linux with kernel 4.17 or newer (5.7 or newer for the cgroup fd), /dev/net/tun, nftables with conntrack, namespaces, root, cgroup v2 recommended, and a KVM VPS rather than OpenVZ/LXC; client: macOS on Apple silicon, or Linux 4.17 or newer, with outbound UDP. The PRD target is at least 50 Mbit/s over two hops on 1-vCPU nodes. The first device test's exit ran within a 0.75 CPU / 300 MB container limit. Nothing has been measured yet.
- **First real measurements (device run 4, 2026-10-15; informal, not the lab method this ticket asks for):**
  - client on macOS arm64: RSS ~70 MiB steady after a 12,908-route table (35 MiB before it; retained Go heap, not growth); about 0.45 of one core at ~94 Mbit/s, i.e. ~200 Mbit/s per core for userspace WireGuard plus the outer transport
  - exit in a container capped at 0.75 CPU: download held at the cap (70-77%), ~94 Mbit/s goodput, i.e. roughly 125 Mbit/s per vCPU; memory peak 72 MiB
  - latency under load: idle tunnel RTT +21 ms over direct; under download, ~170 ms of extra queueing in front of the saturated exit (networkQuality RPM 157 vs 313 direct)

## Log
- 2026-10-14 created in backlog
- 2026-10-15 docs (independent review 2026-10-15): MemoryMax/PidsMax/FairShare defaults mandatory in scope; acceptance and notes on fork-bomb and reply-path flooding
- 2026-10-15 docs: first measured footprint from device run 4
