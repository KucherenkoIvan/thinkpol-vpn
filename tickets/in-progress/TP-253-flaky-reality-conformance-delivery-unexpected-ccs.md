---
id: TP-253
title: "Flaky transport/reality TestConformance/Delivery: 'unexpected ccs message'"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-253
branch: tp-253-reality-ccs-flake
---

## Goal
In TP-239's lab-test-default run (2026-11-19) the reality transport package's TestConformance/Delivery failed once with nginx (the camouflage site) reporting "unexpected ccs message"; a targeted re-run passed 3 of 3. Find what sends a ChangeCipherSpec the site doesn't expect (a TLS 1.3 middlebox-compat CCS at the wrong time, a fallback to the camouflage path mid-handshake, a retry reusing a connection) and fix the cause; if it's a real product behaviour a censor could see, say so plainly.

## Scope
- Reproduce, name what sends the ChangeCipherSpec the site doesn't expect, and fix the cause; say in Notes whether a censor could see it.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-19 created in backlog (seen in lab runs 2026-11-19)
- 2026-11-19 backlog → in-progress, owner: agent-tp-253
