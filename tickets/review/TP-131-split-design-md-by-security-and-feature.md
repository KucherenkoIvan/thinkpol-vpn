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

## Review findings
Round 1 (2026-10-22): correctness (fix first), design (fix first), second opinion (fix first). The moved text keeps its words; what's around it isn't done.
- [x] R1.1 Threat model and Rules exist twice, word for word: DESIGN.md (~9-33) and `docs/design/security.md` (~5-30). Remove them from DESIGN.md and put a short "## Security" pointer to security.md in their place ("read it first: every other design file assumes it"). Drop DESIGN.md ~7's "`RRn` below names its rows", and fix DESIGN.md ~19's "see Node safety" into a link.
- [x] R1.2 Sections in the wrong file: "Node agent" (`desktop-client.md` ~29-35) covers every node (one agent per host, a removed node idles); move it, with the ceiling bullet (`server-agent.md` ~20, both presets), to `overlay.md`. security.md's "IPv6" lines on addressing (the ULA /48, dual stack, the MTU floor, entries over IPv6 as extra paths, ~37 and ~41) are overlay design: move them to `overlay.md` under "IPv6 addressing"; the leak bullets stay. The kill switch and the decided crash posture (`desktop-client.md` ~22-26) are the main fail-closed decision: move them to security.md. End security.md with an "Elsewhere" index of the security invariants that stay with their feature (route table, DNS, server agent, the signed map, the local API), each a link.
- [x] R1.3 References the rewrite missed, and the script's "0 dangling" (it read line by line and resolved a heading against any file): fix the script to join wrapped comment lines, catch bare "DESIGN" (no .md) and prose forms ("DESIGN.md, X", "DESIGN.md's X section"), and resolve each heading in the file the citation names; re-run and log the real count. Known misses: `internal/agent/blobstore.go:199`, `internal/agent/watch.go:12`, `internal/agent/node.go:419`, `internal/agent/resolver.go:27-28,259-260`, `internal/shaping/doc.go:36-37`, `internal/dataplane/router/doc.go:21-22`, `internal/dataplane/transport/doc.go:2-3` (names overlay.md for "Transports own traffic shape", which is in transports.md), `proto/thinkpol/netmap/v1/netmap.proto:82-83` (then `make proto`), `lab/m0_test.go:19`, `lab/censor/doc.go:1-2`; open tickets TP-028, TP-030, TP-032, TP-034, TP-035, TP-038, TP-044, TP-048, TP-063, TP-066, TP-069 (cites DESIGN.md line numbers that no longer exist: point to the heading), TP-086, TP-087, TP-088, TP-091, TP-111. Citations of Open questions and Repository layout stay on DESIGN.md.
- [x] R1.4 Done tickets' history was rewritten though the Log says it wasn't: restore `tickets/done/TP-077-split-design-md.md` ~59 and `tickets/done/TP-099-*.md` ~61 and ~130 from rewrite (only `refs:` front matter may change in done tickets).
- [x] R1.5 Cross-file pointers as plain text: `control-plane.md` ~9 "(see Open questions)" (move that open question to control-plane.md, or link it), `security.md` ~52 "(see the signed map)" → a link; `security.md` ~19 links RESIDUAL-RISKS.md; every design file's lead says "`RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md)".
- [x] R1.6 Workflow docs still describe one file: `tickets/README.md` ~30 (`refs:` comment: PRD ids or `docs/design/<file>.md#anchor`); `tickets/ORCHESTRATION.md` ~74 ("Decisions go into the design file for their topic; DESIGN.md indexes them") and ~117 (DESIGN.md is the entry point and index; split a design file by subtopic when it passes 50 KB); AGENTS.md ~3 ("DESIGN.md and the design files it indexes say how"); README.md ~8.
- [x] R1.7 board.py: any `[A-Z]\d+` passes as a PRD id without a lookup (`Z99` passes): check it against PRD's ids; a bare `DESIGN`/`PRD`/`docs/design/<file>.md` ref passes with no anchor (TP-077's `refs: [DESIGN]` is live): decide and say; accept `RESIDUAL-RISKS.md#…` and `RR\d+` (checked against the table's row ids); strip fenced code blocks before collecting headings, and add GitHub's `-1` suffix for repeated headings. A test file for board.py if there is a place for one, else a self-check in the Log.
- [x] R1.8 Nits: heading levels copied from DESIGN.md (files jump from `#` to `###`/`####`; security's "IPv6"/"Node safety" sit under "Rules"): promote each file's top sections to `##`; `server-agent.md` ~24 repeats the egress bullet as a trailing paragraph: merge; `milestones.md` ~3's glue sentence repeats ~7.

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
- 2026-10-22 review → has-errors (round 1: R1.1-R1.8)
- 2026-10-22 R1.1: DESIGN.md keeps only the pointer — its threat model and rules (word-for-word copies of security.md's) are replaced by a short `## Security` pointer, "read it first: every other design file assumes it"; "`RRn` below names its rows" is dropped from the intro; the threat model's "see Node safety" is a link in security.md
- 2026-10-22 R1.2: the node agent and the node's own ceiling bullet (both presets) moved to overlay.md, the overlay's IPv6 bullets under "IPv6 addressing" there; the kill switch and the decided crash posture moved to security.md, which ends with an "Elsewhere" index of the security invariants that stay with their features (route table, DNS, server agent, signed map, local API), each a link; moved text keeps its words
- 2026-10-22 R1.3: the reference script (/tmp/tp131_design_refs.py, still not committed) now joins wrapped comment lines, catches bare `DESIGN` (no .md) and the prose forms ("DESIGN.md, X", "DESIGN.md's X section"), and resolves every phrase against the file the citation names (headings and bold paragraph leads, GitHub's -1 suffixes for repeats, fenced code holds no headings); it skips history — done tickets, each ticket's Log and Review findings, and the validators' own code. The tree as round 1 left it: 151 references — 37 bare anchors, 24 file links, 4 links, 3 prose, 83 quoted — 22 dangling; after the fixes: 145 — 37 bare, 25 file links, 5 links, 3 prose, 75 quoted — 0 dangling, 0 line pointers. Fixed: the wrapped comments in internal/agent (blobstore, watch, node, resolver twice), shaping, router, transport and netmap.proto (`make proto` re-ran), lab/m0_test and lab/censor; the four round-1 pointers to desktop-client.md "Node agent"/"Kill switch" (.golangci.yml, dataplane/doc.go, firewall/doc.go, routetable/doc.go) repointed to overlay.md and security.md; the quoted and prose forms in TP-028, TP-030, TP-032, TP-033, TP-034, TP-035, TP-038, TP-044, TP-046, TP-048, TP-063, TP-066, TP-069 (its line numbers 99 and 102 now point at server-agent.md), TP-086, TP-087, TP-088, TP-091, TP-111; citations of Open questions and Repository layout stay on DESIGN.md
- 2026-10-22 R1.4: restored TP-077 ~59 and TP-099 ~61 and ~130 word for word from rewrite; the done tickets now differ from rewrite only in refs: front matter (TP-077 and TP-056, see R1.7)
- 2026-10-22 R1.5: cross-file pointers are links: control-plane.md's "see Open questions" links DESIGN.md#open-questions, security.md's "see the signed map" links control-plane.md#the-signed-map, security.md's "Not defended" links RESIDUAL-RISKS.md#not-defended-see-threat-model, and every design file's lead says `RRn` are rows of RESIDUAL-RISKS.md
- 2026-10-22 R1.6: tickets/README.md's `refs:` comment names the accepted forms (PRD ids or RR rows, DESIGN.md#anchor or docs/design/<file>.md#anchor); ORCHESTRATION.md sends decisions to the design file for their topic and says DESIGN.md is the entry point and index — a design file splits by subtopic at 50 KB; AGENTS.md and README.md describe DESIGN.md as the entry point with the design files it indexes
- 2026-10-22 R1.7: board.py checks a PRD id against the PRD's requirement tables (Z99 refused; M0-M5 are milestones, not requirement ids), accepts `RR\d+` against the table's row ids and RESIDUAL-RISKS.md#anchor, resolves anchors per file with fenced code stripped and GitHub's -1 suffixes for repeated headings, and refuses a bare DESIGN/PRD/docs-design ref with no anchor — decided: a ref names a heading, so a bare file pointer says nothing checkable; TP-077's `refs: [DESIGN]` became DESIGN.md#where-the-mechanism-lives and TP-056's #node-agent moved to overlay.md with the section (done tickets: refs: front matter only); the validation is tested in tickets/test_board.py, 9 tests green (`python3 tickets/test_board.py`)
- 2026-10-22 R1.8: every design file's top sections are ## (security's IPv6 and Node safety no longer sit under Rules), server-agent.md's trailing egress paragraph merged into its egress bullet, milestones.md's repeated scope sentence dropped
- 2026-10-22 make lint and make test exit 0 before each commit; merged origin/rewrite (no new commits to carry); docs-only change, no lab run needed
- 2026-10-22 in-progress → review
- 2026-10-22 round 2: correctness and design asked for small fixes, applied by the orchestrator. The ceiling bullet moved into overlay.md's "Node agent", and server-agent.md links it. The runbook's wrapped design citation is now links; prose citations in TP-036, TP-065, TP-080 (the path package doc), TP-085, TP-069 (RR34) and TP-042 (control-plane.md) are repointed. The R1.3 line's "0 dangling" missed the runbook's wrapped citation and these prose forms. board.py reads RESIDUAL-RISKS.md only if it exists; make lint runs tickets/test_board.py
- 2026-10-22 round 2, second opinion: the ceiling citations in internal/agent/doc.go and TP-111 now point to overlay.md "Node agent"; merged after correctness and design round-2 fixes (orchestrator)
