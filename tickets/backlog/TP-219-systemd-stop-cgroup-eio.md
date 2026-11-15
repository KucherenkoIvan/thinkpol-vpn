---
id: TP-219
title: "systemd 252 on Linux 7.0: does `systemctl stop` or `restart thinkpol` hit the same cgroup.procs EIO as `systemctl kill`?"
milestone: M3
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-211]
refs: []
owner: ""
branch: ""
---

## Goal
Know whether stopping or restarting the thinkpol unit under systemd 252 on a Linux 7.0 kernel fails the way `systemctl kill` did in TP-211 ("Failed to send signal SIGKILL to auxiliary processes: Input/output error"), and if it does, whether a member's `systemctl stop thinkpol` or `restart` (and the uninstall that stops the unit) still leaves the host as the agent should: workers gone, rules and routes undone.

## Scope
- In the lab's systemd nodes on a Linux 7.0 host (Docker 29), run the unit through `systemctl stop`, `restart` and `thinkpol service uninstall`, a device and a server (with workers), several times each; record the exit status, the journal's errors and what is left in the unit's cgroup and on the host.
- If the EIO shows: find where it comes from (systemd's cgroup walk while the agent exits, or the kernel's cgroup.procs read) and whether a newer systemd has it; then either work around it in the lab or the unit, or record it as a residual with what a member sees.
- If it doesn't: a lab test that stops and restarts a server's unit and checks its workers end, so a regression shows.

## Out of scope
- `systemctl kill` itself: TP-211 moved the lab tests to `--kill-whom=main`.

## Acceptance
- [ ] The measurements above in the Log, with the host's kernel, systemd and Docker versions.
- [ ] Either a fix or residual for the EIO, or a lab test that stops and restarts a server's unit and checks its workers are gone.

## Notes
- The lab's image is Debian 12 (bookworm), whose systemd is 252, from 2022. A Linux 7.0 kernel is years newer, so the failure may be systemd's age rather than anything a member's host would run: Debian 13 (trixie) ships systemd 257. A trial lab image on Debian 13 would tell the two apart, and is worth its own ticket if the image moves.
- On Docker Desktop's 6.10 kernel the kill never failed.

## Log
- 2026-11-15 created (TP-211 review round 1, R1.3)
