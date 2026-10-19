---
id: TP-114
title: "Supervisor: the ARP filter sits on the output hook"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-103]
refs: [DESIGN#server-agent]
owner: ""
branch: ""
---

## Goal
A space's ARP never reaches the root namespace's neighbour table, as DESIGN ("Server agent") and the comments in `internal/agent/supervisor/isolation_linux.go` say. Today the arp table's chain is attached to the ARP output hook, so the drop never matches.

## Scope
- `isolation_linux.go` (~214 on rewrite): the arp chain is built with `nftables.ChainHookInput`, which is `NF_INET_LOCAL_IN` (1); in the arp family hook 1 is `NF_ARP_OUT`. The kernel lists the chain on `"hook":"output"` (TP-103's isolation goldens show it). On output there is no input interface, so `iifname tp-space*` never matches and a space's ARP (forged sender addresses included) reaches the root's neighbour handling. Attach the chain to the ARP input hook (`NF_ARP_IN`, 0).
- A behavioural lab test: a space sends ARP (a request with a forged sender address) toward its root end; the root's neighbour table gains no entry for it and the drop counter moves. The negative control (the chain on the old hook, or no chain) shows the entry appearing.
- TP-103's goldens: regenerate them with the fixed hook, and say why in the Log.

## Out of scope
- Other isolation rules.

## Acceptance
- [ ] the arp chain is on the ARP input hook (the golden says `"hook":"input"`)
- [ ] lab: a space's forged ARP adds no neighbour entry in the root namespace; the negative control does
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-103's correctness review (2026-10-19) from the isolation golden; present since the supervisor's isolation landed (pre-M1). Nothing crosses between spaces through it; a space can fill or poison the root's neighbour table.

## Log
- 2026-10-19 created in backlog (TP-103 review: security bug, high priority after TP-103)
