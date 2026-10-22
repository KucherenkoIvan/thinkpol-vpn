---
id: TP-131
title: "Split DESIGN.md: security in its own file, design by feature, DESIGN.md links them"
milestone: M2
area: docs
repo: thinkpol-vpn
size: S
depends_on: [TP-077]
refs: []
owner: agent-tp-131
branch: tp-131-split-design-md
---

## Goal
DESIGN.md stops being one file at its size limit. Security has its own document, each feature's design has its own, and DESIGN.md is the short entry point that links them all. Edits in M2 then land in the file for their feature.

## Scope
- DESIGN.md is 49,993 bytes, against a 50,000-byte budget (TP-077), so the next M2 edit would pass it. The owner's rule (tickets/ORCHESTRATION.md "Design documents"):
  - security in its own file;
  - design by feature;
  - the main file links all of them.
- Proposed layout, to be confirmed by reading the file:
  - `docs/design/security.md`: threat model, rules (including rule 7 and its exceptions), the leak guard and fail-closed invariants, node safety.
  - One file per feature area. Candidates: the overlay and the signed map; transports and the server agent; routing, rules and DNS; the control plane, joining and recovery; the desktop client and the local API; the censor lab; milestones.
  - DESIGN.md keeps: what the system is, the architecture overview, the index of design files and of package docs ("Where the mechanism lives"), and the links to RESIDUAL-RISKS.md and PRD.md.
- Every design-section citation in tickets, code comments, PRD.md, RESIDUAL-RISKS.md, AGENTS.md, README.md, lab docs and package docs is updated to the new file and heading. A script lists every reference before and after, and none dangles.
- AGENTS.md and tickets/README.md say which file a change updates.
- Docs only: no text is rewritten except to fit the move. Moved sections keep their words.

## Acceptance
- [x] DESIGN.md is an entry point that links every design file, and each design file has one topic
- [x] security has its own file
- [x] no reference to an old `DESIGN#...` anchor is left dangling (the script's output is in the Log)
- [x] `python3 tickets/board.py --check`, `make lint` and `make test` pass

## Notes
- The board's `refs: [DESIGN#...]` front matter must point to the new `docs/design/<file>#anchor`. Check that board.py accepts the new form, and extend it if it doesn't.

## Log
- 2026-10-22 created in backlog (owner's rule on splitting DESIGN.md)
- 2026-10-22 backlog → in-progress — owner: agent-tp-131, branch: tp-131-split-design-md
- 2026-10-22 proposed file list, per the ticket's candidates read against the file: `docs/design/security.md` (threat model, rules, IPv6 leak guard, node safety), `overlay.md` (data plane, direct paths), `transports.md`, `server-agent.md` (server agent + egress), `routing.md` (rules, route table, DNS, lists), `desktop-client.md` (client, local API, kill switch, node agent), `control-plane.md` (controller, signed map, joining, kernel usage), `lab.md` (censor lab), `milestones.md` (milestones, out of scope); DESIGN.md keeps the intro, the architecture overview, "Where the mechanism lives", repository layout, open questions and the index of design files
- 2026-10-22 the split, as proposed: DESIGN.md 49,993 → 11,534 bytes; docs/design/ gains the nine files above (the whole set is 45.9 KB); moved sections keep their words, only link targets and one glue sentence per file change; AGENTS.md and tickets/README.md now say which file a change updates
- 2026-10-22 reference script (/tmp, not committed): before 730 references — 94 `DESIGN#` anchors, 122 quoted-heading, 501 plain mentions, 9 line pointers, 4 links — 57 unresolved against the headings; after the split 241 references, 0 dangling; rewritten: all 94 anchor refs to `docs/design/<file>.md#anchor`, 4 links, 49 quoted-heading references in code comments, proto, .golangci.yml, AGENTS.md and lab docs, plus glue in AGENTS.md, tickets/README.md, PRD.md, RESIDUAL-RISKS.md; plain DESIGN.md mentions stay (it is the entry point); the 9 line pointers and quoted forms inside done tickets' Logs left as history (Logs are append-only)
- 2026-10-22 board.py --check validates every ref as a PRD requirement id or a design file#anchor resolved against the headings (landed in the split commit); docs-only change, no lab run needed; make lint and make test exit 0 before each commit; merged origin/rewrite (no new commits)
- 2026-10-22 in-progress → review
