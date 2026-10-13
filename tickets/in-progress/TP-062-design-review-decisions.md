---
id: TP-062
title: "Design decisions from the independent design review (2026-10-13)"
milestone: M1
area: docs
repo: thinkpol-vpn
size: M
depends_on: []
refs: [DESIGN#threat-model, DESIGN#server-agent-one-worker-per-space, A2, D4]
owner: "agent-design-decisions"
branch: "tp-062-design-review-decisions"
---

## Goal
The owner's decisions on the independent design review (2026-10-13) are written into PRD.md, DESIGN.md and the tickets they change, so each one is a decision on record and none is left to an implementer's guess. Documentation only: no code.

## Scope
- DESIGN.md and PRD.md text for each decision: pre-auth surface, replay behaviour, server-side fingerprint, invites, crash posture, the two threat-model additions, and the smaller notes.
- The panel's authentication and authorization is put on hold as an open question, not designed.
- Notes and acceptance items in the tickets each decision touches; new backlog tickets for the work they create.

## Out of scope
- Designing the admin panel's authentication and authorization (the owner hasn't decided how the panel is organised).
- Any code.

## Acceptance
- [ ] every decision above is in DESIGN.md or PRD.md, in the style of the existing text
- [ ] each touched ticket carries the note or acceptance item, with a Log line
- [ ] the new backlog tickets exist: gatekeeper, Reality transport research, on-device VPN detection
- [ ] `python3 tickets/board.py --check` and `make lint` pass

## Notes
- The review itself is gitignored and stays out of the repo; it is cited as "independent design review, 2026-10-13".
- TP-019 is in review on its own branch, so its ticket file isn't touched here: the macOS crash-posture note lives in TP-046 and TP-048, and DESIGN.md says macOS must meet it too. TP-018 is done: its Log gets a line and the note goes to TP-048.

## Log
- 2026-10-13 created directly in in-progress — owner: agent-design-decisions, branch: tp-062-design-review-decisions
