---
id: TP-218
title: "Linux DNS: resolv.conf edge cases from TP-117's round 1"
milestone: M3
area: dataplane/dns
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-117]
refs: [RR5]
owner: ""
branch: ""
---

## Goal
Four resolv.conf edge cases found in TP-117's first review are either handled or named in RR5 with their effect.

## Scope
- A symlink to a file holding the node's exact managed content outlives disconnect: restoreResolvConf skips non-regular files.
- A read-only /etc with a read-write bind-mounted resolv.conf: writeFile's EROFS isn't EBUSY or EXDEV, so the in-place fallback is never tried.
- A script that strips the managed header turns the node's servers into the "original".
- A partial non-empty link target while untold is taken: there is no settle on linkedOriginal.

## Out of scope
- IN_MODIFY (TP-215) and the bind-mount events (TP-216).

## Acceptance
- [ ] Each case has a test that shows today's behaviour and, where fixed, a mutation that brings it back; evidence: the tests and mutations in the Log.
- [ ] A case left as it is is named in RR5 and the dns package doc with its trigger and effect; evidence: the diff.
- [ ] `make lint`, `make test` pass, and `make lab-test` if Linux-only code changed.

## Notes
- Source: TP-117's review round 1 (out-of-scope findings).

## Log
- 2026-11-14 created in backlog (from TP-117 round 1)
