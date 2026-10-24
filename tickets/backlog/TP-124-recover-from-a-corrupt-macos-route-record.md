---
id: TP-124
title: "macOS: recover from a corrupt route record"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A corrupt route record under `/private/var/db/thinkpol/netcfg` doesn't leave a device unable to connect until someone deletes the file by hand.

## Scope
- Today (TP-108) a corrupt record of another owner fails this node's route-table survey (and the default-route lookup) with an error naming the file; recovery was handed to TP-102, which didn't take it.
- Decide what is safe: a record that can't be parsed says nothing about which routes are whose. Options: quarantine the file and treat its owner's routes as foreign (never removed by us), or remove only routes that match a parsed record and leave the rest. Never delete routes we can't prove are ours.
- Health says a record was set aside, and the log names the file.

## Acceptance
- [ ] a unit test with a corrupt record of another owner: the survey succeeds, the record is set aside, no route of that owner is removed
- [ ] the same for the node's own record at start
- [ ] `make lint`, `make test` pass

## Notes
- From TP-077's residual-risks research (2026-10-22); TP-108 R2.7 handed recovery to TP-102, which didn't add it.
- **Order (owner, 2026-10-24).** In the before-M2 list: done before the M2 lanes start. TP-108 made another owner's corrupt route record a hard connect failure, with no recovery but deleting the file by hand. The 2026-10-24 macOS device run's corrupt-record step was inconclusive; TP-144's re-run checks it again.

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
- 2026-10-24 docs: in the before-M2 list (TP-108 made a foreign corrupt record a hard connect failure)
