---
id: TP-276
title: "Forwarding's record is saved after its sysctl writes"
milestone: M2
area: agent/supervisor
stream: core
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-276"
branch: "tp-276-forwarding-record-before-writes"
---

## Goal
`enable` (internal/agent/supervisor/forwarding.go) writes accept_ra and the forwarding switch (~240, ~257) and `ensure` saves the record only after (~217). A crash (SIGKILL, OOM) in that window, or a failed save after a successful `enable` (`applyTables` only logs a warning), leaves forwarding on with no record. The next supervisor loads nothing, `installIsolation` rebuilds with `owned` false (isolation_linux.go ~323), and `enable` won't own a switch already at 1 (~224): a restarted exit node forwards that family for everyone, unconfined by its isolation tables, for the rest of the boot, with accept_ra 2. When this is done, every sysctl the supervisor writes is recorded before it is written, or put back, whatever the point of failure.

## Scope
- Save the record (Main.Written "1", Before) before flipping the switch, so a successor whose switch never flipped still puts accept_ra back; then save Side after.
- Treat a failed save as a failed apply, not a warning.
- `load` drops a family whose switch no longer holds what was written together with its Before entries (forwarding.go ~142-149): if the supervisor crashes and an admin or networkd turns that forwarding off, accept_ra stays 2 for the rest of the boot (low harm: 2 acts like 1 while forwarding is off). Have `load` put back the Before entries of a family it doesn't adopt when they still read their Written value.
- Update the "Root forwarding" section of the package doc (doc.go) and drop its "Not yet" line.

## Out of scope
- Forwarding someone else turned on (a container runtime): left alone, as now.

## Acceptance
- [ ] Tests that kill or fail at each point (after the accept_ra writes, after the switch, a failed save) and show the successor puts everything back or owns it (confined by its tables).
- [ ] A test for `load` with a family's switch turned off underneath: its accept_ra put back.
- [ ] Every new test mutation-checked, mutations in the Log.
- [ ] `make lab-gotest PKG=./internal/agent/supervisor/...` green, the reset undoing nothing.

## Notes
- Found in TP-270's review (R1.5) and its implementer's out-of-scope note.

## Log
- 2026-11-22 created in backlog (TP-270 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-276
