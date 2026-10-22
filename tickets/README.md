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

`python3 tickets/board.py` prints the board, the tickets that need a human, and the tickets that are ready to start. `--next-id` prints the next free TP id, counting ids that exist only on local or remote branches (`--next-id KRN` does the same for the separate KRN series); `--check` validates frontmatter and dependencies; `--waves` groups unfinished tickets by what can run in parallel. Suggestions for running several tickets at once are in [ORCHESTRATION.md](ORCHESTRATION.md).

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
needs_human: macos        # optional: decision | macos | windows | person
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

**`needs_human`** (optional) marks a ticket that can't be finished by agents alone. `board.py` lists such unfinished tickets in a separate NEEDS HUMAN section and marks them with `!` in `--waves`; `--check` rejects other values.

| Value | What the author has to do |
|---|---|
| `decision` | Pick between options (e.g. a library or framework). Agents prepare a short comparison with a recommendation; the author picks. |
| `macos` | Run something on a real Mac (`sudo`, a real network). |
| `windows` | Run something on a real Windows machine or VM. |
| `person` | Something only a real person can do (e.g. a hand-off test with a non-technical member). |

For `macos`, `windows` and `person`, the policy is: agents build and test everything they can in the lab, then hand the author a short checklist of what is left to run by hand. Acceptance boxes that depend on the checklist are checked once the author has run it and the results are recorded in `## Notes`. A `needs_human` ticket is not `blocked`: it stays in its normal column, and the field only says that a human is needed somewhere along the way.

## Moving a ticket

Always `git mv`, and append a line to `## Log` in the same commit:

```
- 2026-10-10 backlog → in-progress — owner: agent-transport, branch: tp-005-udp-transport
```

| From → to | Allowed when |
|---|---|
| backlog → in-progress | every `depends_on` ticket is in `done/`; `owner` and `branch` are set |
| in-progress → review | every acceptance box is checked, each with evidence produced in the ticket's branch, except boxes that depend on a `needs_human` checklist: they stay unchecked, with the checklist in `## Notes`; the Log says what couldn't be verified (device-only behaviour, platform assumptions); `make lint` and `make test` pass (and the lab checks the ticket names) |
| review → done | review found nothing blocking, every box is checked (a box that waits on a device run may stay open only if the owner agreed to merge before the run; the Log says so), and the branch is merged into `rewrite` |
| review → has-errors | review found problems; they are written into a `## Review findings` section as checkboxes |
| has-errors → in-progress | someone picks the findings up; every finding is checked before review again |
| any → blocked | a `## Blocked by` section says exactly what is missing and who can provide it |
| blocked → previous column | the blocker is resolved; the resolution is written into `## Notes` |

Waiting for a dependency is **not** blocked: such tickets stay in `backlog/` and simply aren't ready yet.

**Work in progress:** at most 4 tickets in `in-progress/` at once, each on its own branch (and its own git worktree when worked in parallel).

## Branches

One branch per ticket, named `<id-lowercase>-<slug>` (e.g. `tp-005-udp-transport`), cut from `rewrite` and merged back into `rewrite`. `KRN-` tickets branch from go-kernel's `master` and follow go-kernel's own rules (docs completeness, tagged releases); the ticket here records the released tag in `## Notes`.

## Splitting an epic

Create the children with new ids and `split_from: <epic id>` in their frontmatter, move the epic's dependents to depend on the right children, then `git rm` the epic. The children's notes carry anything worth keeping from it.

## Source of truth

Tickets implement [PRD.md](../PRD.md) and [DESIGN.md](../DESIGN.md), with [RESIDUAL-RISKS.md](../RESIDUAL-RISKS.md) and the package docs DESIGN.md links. If a ticket and the docs disagree, the docs win; if the docs are wrong, fix them in the same branch and say so in the ticket's log.
