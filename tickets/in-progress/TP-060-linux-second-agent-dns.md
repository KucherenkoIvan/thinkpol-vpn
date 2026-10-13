---
id: TP-060
title: "A second `thinkpol up` must not undo a running agent's DNS (Linux)"
milestone: M1
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-020, TP-022]
owner: "cursor-opus-tp060"
branch: "tp-060-agent-lock-linux"
---

## Goal
On Linux, a second `thinkpol up` on a node where an agent is already running does not touch the host. Today it runs the start-up DNS restore (resolv.conf, or systemd-resolved) before it fails at netcfg's per-owner lock, so the running agent's DNS is undone while its tunnel stays up. After this, the second start is refused before any cleanup, and the running agent's DNS stays as it was. This brings Linux in line with macOS, where TP-019 takes a host-wide agent lock before the start-time cleanups.

## Scope
- Take a host-wide agent lock on Linux (`/var/run/thinkpol/agent.lock`, flock, the same path and semantics as the macOS `hostLock` in TP-019) at the start of `thinkpol up`, before any start-up cleanup: the DNS restore and the route-table clear.
- A second start that cannot get the lock exits with "another agent is running" and changes nothing on the host.
- The lock is released when the agent exits, as on macOS.

## Out of scope
- macOS: TP-019 owns its lock.
- The per-owner netcfg lock and its semantics stay as they are; the host lock sits in front of it.
- Installing the agent as a service and the lock's ownership under systemd (TP-046).

## Acceptance
- [ ] lab test: start agent A on a node; start agent B on the same node. B exits with "another agent is running", and A's DNS config (resolv.conf, or the systemd-resolved state if that is what A set) is unchanged, compared before and after B's run
- [ ] `make lint` and `make test` pass

## Notes
- Found in TP-019's review (branch `tp-019-macos-data-plane`, round 2 notes): on Linux a second `thinkpol up` fails at netcfg's per-owner lock only after its start-time resolv.conf restore, which undoes the running agent's DNS. macOS has the host lock (`hostLock`) for this; Linux could take the same before the cleanups.
- The start-time cleanups are `dns.RestoreSystem` and `routetable.Clear`. The lock has to come before both, and before anything else that writes to the host.

## Log
- 2026-10-13 created in backlog
- 2026-10-13 backlog → in-progress — owner: cursor-opus-tp060, branch: tp-060-agent-lock-linux
