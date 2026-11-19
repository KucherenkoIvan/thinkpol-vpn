---
id: TP-256
title: "reality's start-up target detection without the CCS probe"
milestone: M3
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: M
needs_human: decision
depends_on: []
refs: [RR31, RR32]
owner: ""
branch: ""
---

## Goal
REALITY's detection at a server's first Listen sends the camouflage site extra ChangeCipherSpec records; the site's error log then records the server's IP (a census of REALITY servers for whoever runs or can compel the site).

## Scope
- A design note first (docs/design/, the reality transport section) on running thinkpol's own detection of the target's post-handshake records without the ChangeCipherSpec probe and pre-storing the results, so REALITY skips its own detection (or an upstream switch, if one appears), with what is lost (the ChangeCipherSpec tolerance only matters for authenticated connections); approved by the owner before code.
- Whether pre-storing works is open: thinkpol already wraps GlobalPostHandshakeRecordsLens (recordsStore), and REALITY reads GlobalMaxCSSMsgCount only if it is set; reviewers of TP-253 (2026-11-19) disagreed on whether REALITY then skips its probe.

## Out of scope

## Acceptance
- [ ] Design note approved (owner, date).
- [ ] The lab shows no extra CCS records reach the target at a server's start (capture), and conformance still passes.
- [ ] The RR row narrowed or closed.

## Notes

## Log
- 2026-11-19 created in backlog (TP-253 review)
