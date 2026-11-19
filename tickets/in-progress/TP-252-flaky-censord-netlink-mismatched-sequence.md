---
id: TP-252
title: "Flaky lab: censord fails to start with 'netlink validate: mismatched sequence'"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-252
branch: tp-252-censord-netlink-seq
---

## Goal
In a full lab on TP-251's branch (2026-11-19, three other labs running) the censor-matrix cell reality × fully-encrypted errored because censord failed to start: "register on queue 100: netlink validate: mismatched sequence in netlink reply"; a targeted re-run of the cell passed. Find which netlink call (nfqueue bind, nftables, conntrack over ctnetlink) gets a reply with a sequence number it didn't send (a shared netlink socket used concurrently? a stale reply from a previous censord run in the same netns? a library bug), and fix the cause.

## Scope
- Reproduce, name which netlink call gets the reply it didn't send and why, and fix the cause.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-19 created in backlog (seen in lab runs 2026-11-19)
- 2026-11-19 backlog → in-progress, owner: agent-tp-252
