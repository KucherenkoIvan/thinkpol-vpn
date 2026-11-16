---
id: TP-232
title: "Restoring resolv.conf can overwrite a write that lands during its sync"
milestone: later
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR5]
owner: ""
branch: ""
---

## Goal
TP-220 made a take-back check, right before its rename, that the file still holds what was read. Restore and putting back the original (internal/dataplane/dns/resolvconf.go, the restore path) still rename with no such check, so a host write (dhclient, NetworkManager) landing during Restore's own temp-file sync is renamed over, and the previous network's resolvers are left after stop until the host writes again. doc.go and RR5 describe this window since TP-220.

## Scope
- Restore applies the take-back's check before its rename.

## Out of scope

## Acceptance
- [ ] Restore applies the same check before its rename and leaves a newer host write in place; a test with a writer appending during the sync; mutation-checked.
- [ ] doc.go and RR5 updated.

## Notes
- After the MVP (orchestrator default, 2026-11-16).

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
