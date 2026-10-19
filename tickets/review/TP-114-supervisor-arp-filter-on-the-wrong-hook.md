---
id: TP-114
title: "Supervisor: the ARP filter sits on the output hook"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-103]
refs: [DESIGN#server-agent]
owner: "agent-claude"
branch: "tp-114-supervisor-arp-filter-on-the-wrong-hook"
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
- [x] the arp chain is on the ARP input hook (the golden says `"hook":"input"`): `isolation_linux.go` `arpHookIn` (NF_ARP_IN, 0); the three `testdata/isolation-*.golden` regenerated from the kernel's listing, `TestIsolationRulesetGolden` passes (2023a9b)
- [x] lab: a space's forged ARP adds no neighbour entry in the root namespace; the negative control does: `TestForgedARPIsDropped` (`arp_linux_test.go`), input=true: the arp chain's counter moves and `ip neigh` has no entry for the forged sender; input=false (test-only `Options.arpOnOutput`, the old hook): the root learns it. With the production hook set back to 1, input=true fails (0 drops)
- [x] `make lint`, `make test`, `make lab-test` pass (exit 0 each, on 2023a9b; lab-test LAB_P=4, 35 node packages)

## Notes
- Found by TP-103's correctness review (2026-10-19) from the isolation golden; present since the supervisor's isolation landed (pre-M1). Nothing crosses between spaces through it; a space can fill or poison the root's neighbour table.

## Log
- 2026-10-19 created in backlog (TP-103 review: security bug, high priority after TP-103)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-114-supervisor-arp-filter-on-the-wrong-hook
- 2026-10-19 fixed: the arp chain on NF_ARP_IN (google/nftables and x/sys/unix name no arp hooks, so a named constant); lab test with negative control; the three isolation goldens regenerated, and a diff against the old ones shows the arp chain's hook (output → input) as the only change; DESIGN "Server agent" already says what the fix makes true, left unchanged
- 2026-10-19 in-progress → review
