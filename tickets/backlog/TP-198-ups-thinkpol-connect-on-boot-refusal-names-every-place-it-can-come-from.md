---
id: TP-198
title: "up's THINKPOL_CONNECT_ON_BOOT refusal names every place it can come from"
milestone: later
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-166]
refs: []
owner: ""
branch: ""
---

## Goal
When `up` refuses THINKPOL_CONNECT_ON_BOOT, its message names every place the value can come from, so the operator isn't sent to reinstall the service in a loop.

## Scope
- The refusal in `up` (cmd/thinkpol). The message names the possible sources: an old service definition (fix: reinstall); a systemd drop-in or `systemctl set-environment`; `launchctl setenv`.
- A reinstall fixes only the first source. The message must say that the other two are not fixed by reinstalling.

## Out of scope
Changing which values are accepted, or how the service definition is written. This ticket changes the message only.

## Acceptance
- [ ] a unit test on the message: it names each of the three sources, and says that only the old service definition is fixed by reinstalling
- [ ] `make lint`, `make test` pass

## Notes
- From TP-166's delta check, 2026-11-07.

## Log
- 2026-11-07 created in backlog
