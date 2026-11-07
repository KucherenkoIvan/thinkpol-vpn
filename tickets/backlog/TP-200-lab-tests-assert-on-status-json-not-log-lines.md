---
id: TP-200
title: "Lab tests assert on `status -json`, not log lines"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-168]
refs: []
owner: ""
branch: ""
---

## Goal
Lab tests read facts from `thinkpol status -json` and start nodes through one shared helper, so a change to a CLI flag or a log line no longer ripples into the lab. Today the lab greps CLI flags and log lines: TP-111 had to edit 16 lab files, and one test greps `mode=device`.

## Scope
- Move lab assertions that grep a log line for a fact `status -json` reports onto the `status -json` fields.
- One shared node-start helper in the lab; tests stop building their own `up` command lines.
- Log-line assertions stay only where the log line is the thing under test.

## Out of scope
- Adding fields to `status -json`: that is TP-168; a missing field is a new ticket, not a grep.

## Acceptance
- [ ] No lab test greps a log line for a fact `status` reports; evidence: a grep over the lab tests that finds none.
- [ ] Lab tests start nodes through the one helper; evidence: a grep for direct `up` command lines in the lab tests that finds none outside the helper.
- [ ] The remaining log-line assertions are listed, each with a reason; evidence: the grep listing in this ticket's Log.
- [ ] `make lint`, `make test`, `make lab-test` pass.

## Notes
- Source: stream review 2026-11-07 (orchestrator).
- TP-168 delivers `status -json` with `schema_version`; the board shows it as the ticket for it.

## Log
- 2026-11-08 created in backlog
