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
- [x] every decision above is in DESIGN.md or PRD.md, in the style of the existing text
- [x] each touched ticket carries the note or acceptance item, with a Log line
- [x] the new backlog tickets exist: gatekeeper, Reality transport research, on-device VPN detection
- [x] `python3 tickets/board.py --check` and `make lint` pass

## Notes
- The review itself is gitignored and stays out of the repo; it is cited as "independent design review, 2026-10-13".
- TP-019 is in review on its own branch, so its ticket file isn't touched here: the macOS crash-posture note lives in TP-046 and TP-048, and DESIGN.md says macOS must meet it too. TP-018 is done: its Log gets a line and the note goes to TP-048.

- **Changed.** DESIGN.md: Threat model (member-device compromise, apps on a member's device, the CNAME leak, the honest-binary scope), transports (`reality`-style row, server-side tells, the set-aside bridge node), Server agent (pre-auth gatekeeper, replay takes the camouflage path and the token window, bounded state, per-node camouflage target), DNS, route table (crash sentence), Desktop client (crash posture), Joining (pending devices, update key), Recovery key, Admin panel, Milestones (M1), Open questions (panel). PRD.md: user stories, D4, D7, A2, Trust, Release plan (M1), Risks, Decisions (Reality, crash posture, invites), Open questions.
- **Tickets.** Created: TP-063 (gatekeeper), TP-064 (Reality research), TP-065 (on-device VPN detection). Notes or acceptance: TP-010, TP-018 (Log), TP-023, TP-026, TP-028, TP-032, TP-036, TP-038, TP-039, TP-042, TP-043, TP-044, TP-046, TP-048.
- **Not done on purpose.** The panel's authn/authz is not designed. The "sealed datagrams authenticate only the recipient" point of the review (section 8) was not among the owner's decisions and isn't written down.

## Log
- 2026-10-13 created directly in in-progress — owner: agent-design-decisions, branch: tp-062-design-review-decisions
- 2026-10-13 in-progress → review — docs and tickets written; `python3 tickets/board.py --check` and `make lint` pass
- 2026-10-13 review → done — merged into rewrite
