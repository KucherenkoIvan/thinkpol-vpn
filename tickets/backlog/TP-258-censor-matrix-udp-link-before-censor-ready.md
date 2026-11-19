---
id: TP-258
title: "The censor matrix's udp row brings its link up before the censor is ready"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
setupUDP (lab/results_test.go ~:1407-1412) starts both agents and waits for linkUp before startCensor, so the udp link's handshake crosses the router with no censor table (TP-236's "link up 0.3 s before censord was ready"). judgedFromTheStart (lab/reality_matrix_test.go ~:369-372) checks only reality's flow, so a held udp cell (wireguard-rhythm) can't notice a censor that started mid-flow and missed the handshake that anchors the rekey timing: a possible pass for the wrong reason in an M2 gate input. Start the udp device after the censor is ready (as realityUp does), and make judgedFromTheStart take the row's flow matcher; all verdicts unchanged.

## Scope
- Start the udp row's device after "censor ready", as realityUp does for reality.
- judgedFromTheStart takes the row's flow matcher, so the udp row's held cells check their own flow.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- Found in TP-252's review: lab/censor/doc.go said every test starts its traffic after "censor ready"; the udp row is the exception.

## Log
- 2026-11-19 created in backlog (TP-252 review)
