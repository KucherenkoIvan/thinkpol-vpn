---
id: TP-257
title: "reality handoff workers set the same ChangeCipherSpec tolerance as the main listener"
milestone: M3
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Reviewers of TP-253 (2026-11-19) noticed that handoff workers never get GlobalMaxCSSMsgCount (they are handed the target's records, not REALITY's detection), so they may tolerate a different number of useless records than the main listener on authenticated connections. Check whether a client or prober can observe the difference, and make them consistent.

## Scope
- Handoff workers get the main listener's ChangeCipherSpec tolerance for each target, server name and ALPN, as they get its records.

## Out of scope

## Acceptance
- [ ] Handoff workers and the main listener behave the same (test).
- [ ] Whether the difference was observable, in Notes.

## Notes

## Log
- 2026-11-19 created in backlog (TP-253 review)
