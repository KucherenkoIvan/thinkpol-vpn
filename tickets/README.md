# Tickets

A kanban board in plain files. **A ticket's status is the directory it sits in**, never a field inside the file, so the two can't disagree.

```
tickets/
  backlog/       not started (ready once every dependency is in done/)
  in-progress/   being worked on, has an owner and a branch
  blocked/       can't move until something outside the ticket happens (usually a decision)
  review/        implementation finished, acceptance criteria met, waiting for review
  has-errors/    review or verification found problems, listed in the ticket
  done/          reviewed and merged into the `rewrite` branch
```

`python3 tickets/board.py` prints the board and the tickets that are ready to start. `--next-id` prints the next free id; `--check` validates frontmatter and dependencies; `--waves` groups unfinished tickets by what can run in parallel. Suggestions for running several tickets at once are in [ORCHESTRATION.md](ORCHESTRATION.md).

## Ticket files

`<ID>-<slug>.md`, e.g. `TP-005-udp-transport.md`. Ids are never reused or renumbered. `TP-` tickets are work in this repo; `KRN-` tickets are work in go-kernel that this project needs.

```markdown
---
id: TP-005
title: Transport port and udp transport
milestone: M0
area: dataplane/transport
repo: thinkpol-vpn        # or go-kernel
size: M                   # S | M | L | epic
depends_on: [TP-001]
refs: [C1, C6]            # PRD requirement ids and DESIGN.md sections
owner: ""                 # set when moved to in-progress
branch: ""                # set when moved to in-progress
---

## Goal          one paragraph: what exists when this is done, and why
## Scope         what to build
## Out of scope  what not to build here, and where it goes instead
## Acceptance    checkboxes; all checked before review
## Notes         decisions, pointers, gotchas
## Log           append-only, one dated line per move
```

**Sizes.** `S`: a small change. `M`: one focused branch. `L`: several days of work but still one coherent change. `epic`: too big to start; split it first (see below).

## Moving a ticket

Always `git mv`, and append a line to `## Log` in the same commit:

```
- 2026-10-10 backlog → in-progress — owner: agent-transport, branch: tp-005-udp-transport
```

| From → to | Allowed when |
|---|---|
| backlog → in-progress | every `depends_on` ticket is in `done/`; `owner` and `branch` are set |
| in-progress → review | every acceptance box is checked; `make lint` and `make test` pass (and the lab checks the ticket names) |
| review → done | review found nothing blocking, and the branch is merged into `rewrite` |
| review → has-errors | review found problems; they are written into a `## Review findings` section as checkboxes |
| has-errors → in-progress | someone picks the findings up; every finding is checked before review again |
| any → blocked | a `## Blocked by` section says exactly what is missing and who can provide it |
| blocked → previous column | the blocker is resolved; the resolution is written into `## Notes` |

Waiting for a dependency is **not** blocked: such tickets stay in `backlog/` and simply aren't ready yet.

**Work in progress:** at most 3 tickets in `in-progress/` at once, each on its own branch (and its own git worktree when worked in parallel).

## Branches

One branch per ticket, named `<id-lowercase>-<slug>` (e.g. `tp-005-udp-transport`), cut from `rewrite` and merged back into `rewrite`. `KRN-` tickets branch from go-kernel's `main` and follow go-kernel's own rules (docs completeness, tagged releases); the ticket here records the released tag in `## Notes`.

## Splitting an epic

Create the children with new ids and `split_from: <epic id>` in their frontmatter, move the epic's dependents to depend on the right children, then `git rm` the epic. The children's notes carry anything worth keeping from it.

## Source of truth

Tickets implement [PRD.md](../PRD.md) and [DESIGN.md](../DESIGN.md). If a ticket and the docs disagree, the docs win; if the docs are wrong, fix them in the same branch and say so in the ticket's log.
