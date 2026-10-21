---
id: TP-077
title: "Split DESIGN.md into model and package docs"
milestone: M2
area: docs
repo: thinkpol-vpn
size: L
depends_on: [TP-023]
refs: [DESIGN]
owner: "agent-tp-077"
branch: "tp-077-split-design-md"
---

## Goal
DESIGN.md keeps the model, invariants and decisions. Mechanism moves into package docs (`doc.go`). A residual-risks table collects every accepted residual so leak promises in PRD R4 and D6 can be stated honestly against it.

## Scope
- Shrink DESIGN.md to the model, invariants and architecture decisions.
- Move mechanism detail into per-package `doc.go` (or equivalent package docs), each reachable from the model doc.
- Add a residual-risks table covering at least: the CNAME leak, the macOS TunnelVision window, the IPv4 window when the TUN drops, udp's exposure, the replay-after-restart caveat, and any others found while splitting.
- Update PRD R4 and D6 to qualify leak promises against that table.

## Out of scope
- Changing the technical behaviour described; this is documentation structure only.

## Acceptance
- [ ] DESIGN.md is under a third of its current size (not met: see the Log; proposed size below)
- [x] every moved mechanism is reachable from a package doc
- [x] the residual-risks table exists, and PRD R4 and D6 reference it

## Notes
- The author wants extensive documentation for this; it is deferred until after M1.
- **Size (2026-10-22).** DESIGN.md went from 105,200 bytes (after TP-112) to 77,013: 63.5 KB of model and the 13.5 KB residual-risks table. A third (35 KB) would drop model content: the threat model, the rules, the control plane's aggregates and the signed map's invariants, the planned server-agent decisions (gatekeeper, ClientHello auth, replay path), which have no package to move to yet, and the residual table itself. Proposed acceptance: about 60% of the old size for the model plus the residual table (~65 KB model at most), or the table in a file of its own if the size matters more than keeping risks next to the model.

## Log
- 2026-10-15 created in backlog
- 2026-10-21 backlog → in-progress — owner: agent-tp-077, branch: tp-077-split-design-md
- 2026-10-22 package docs carry DESIGN's mechanism, checked against the code (001c1b7): routetable, netcfg, ifbind, trusteddir, firewall, dns, router, supervisor, worker, ipc, egress, udp, agent, localapi, logring, dataplane, tun, path, transport, shaping, rules, blobs, lists, netmap, wg, lab/censor; TP-112's exit-DNS order and refusal reporting and TP-120's reply-address order carried in
- 2026-10-22 DESIGN.md keeps the model, invariants and decisions, each section linking its package docs, plus an index (0df3032); new rule 7 (what can't be resolved fails closed) states what the sections already said
- 2026-10-22 DESIGN "Residual risks" RR1-RR50 built from DESIGN, tickets/done Notes and Logs and the code; PRD R4 is qualified by RR1-RR11, D6 by RR12-RR17
- 2026-10-22 ticket refs to anchors that never existed fixed: DESIGN#data-plane, #server-agent, #lab point at the headings they meant; board.py --check doesn't validate anchors; AGENTS.md and README.md say where the mechanism lives
- 2026-10-22 size not met: 105,200 → 77,013 bytes (63.5 KB model + 13.5 KB residual table); a third would drop model content, proposed size in Notes
- 2026-10-22 DESIGN vs code (docs now follow the code, no code changed): no camouflage exists, unauthenticated udp is dropped (node.go builds supervisor.Listener without one); udp's evicted-sender ring (udp/replay.go) and the supervisor's 8 reply addresses per link (replies.go) forget their oldest, not refuse; the agent never writes map.bin (TP-037); logs are readable only through the local API's TailLogs, not over the overlay
- 2026-10-22 DESIGN vs code, more: the local API shows workers' last exit (convert.go); the local API's socket directory isn't opened through trusteddir (listen_unix.go); worker limits fall back only to RLIMIT_NPROC and a failed cgroup leaves none (options.go:154-156 comment overstates); hop-group scoring, lowest-latency and spread aren't built (TP-031); WireGuard keepalives don't use WriteControl; lists have no default source and no geosite importer; the map's key epoch can't change yet (TP-036)
- 2026-10-22 DESIGN vs code, firewall/routetable/dns: a main ruleset replaced without the pf hook makes the guard unsupported for good; ULA DNS upstreams get pf rules; the Linux guard's support probe repeats until it succeeds; the nftables ND rule passes ICMPv6 133-137; the re-apply loop is the Enforcer's own watcher; on a pre-4.17 kernel rules are added, found untagged and deleted; macOS direct routes are skipped where another route holds the prefix; resolved's 127.0.0.54 stub too; macOS DNS checks every 2 s while unwatched
- 2026-10-22 out of scope, for filing: stale comments netcfg/netcfg_other.go:11 and dns/system_other.go "(macOS: TP-019)", agent/config.go:43 -log-level help "stderr only", udp/router.go:24-27 "worker's Listener still drops" replays after a supervisor restart (it doesn't, TP-069), udp's replay-after-restart window is up to 10 min where TP-069 says 5
- 2026-10-22 out of scope, for filing: TP-046 doesn't carry the pf boot race DESIGN gives it; TP-048 asks for ND/MLD hop-limit exemptions on macOS, which pf can't match; TP-059 says nothing leaks when the TUN drops (RR20 says IPv4 does for a debounce); no owner for exit DoT/DoH and DNS spoofing (RR8), corrupt route-record recovery (TP-108 handed it to TP-102, not done), TP-062's "authenticate only the recipient"; RR21 (a removed or retrying device's traffic goes direct) is newly named
- 2026-10-22 merged origin/rewrite twice (TP-112, TP-120); make lint and make test green before each commit; tests: none added or changed (documentation only, no mutation checks apply)
- 2026-10-22 make lab-test green on 95738ab (LAB_P=1, other labs running); an earlier full run was green on 0df3032 (LAB_P=4)
- 2026-10-22 not verifiable here: the macOS and device-only claims moved into firewall, routetable, netcfg and dns docs were checked against code and tests only, not on a device (TP-096, TP-085)
- 2026-10-22 in-progress → review
