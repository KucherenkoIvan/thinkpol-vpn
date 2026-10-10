# Orchestration notes

Suggestions for running several tickets at once, written down while the board was set up (2026-10-10). **None of this is a rule**: the rules are in [README.md](README.md). Treat these as a starting point, and change or drop anything that doesn't hold up in practice.

## Parallelism

`python3 tickets/board.py --waves` groups unfinished tickets by dependency depth: everything in one wave can run in parallel once the earlier waves are done. When the board was created there were 14 waves, 3–6 tickets wide. Parallelism shortens each wave, but the waves still come one after another.

The board's WIP limit (3) is conservative. The machine the board was set up on (8 CPUs, 11 GB for Docker) could probably take 4–5 agents at once. The lab is the likelier bottleneck (see below).

## A possible loop

1. Pick ready tickets (`board.py` lists them), up to the WIP limit.
2. One agent per ticket, each in its own git worktree on the ticket's branch.
3. When an agent moves its ticket to `review/`, an adversarial reviewer agent tries to break the change; findings send it to `has-errors/`.
4. Merge into `rewrite` one ticket at a time, rebasing the next one first; move the ticket to `done/` in the same commit.

## Suggested changes to tickets

Not applied yet; worth considering before wave 1:

- **Lab isolation per worktree (TP-002).** As written, two lab runs at once would collide on container names and networks. Adding "lab runs are isolated per worktree" to TP-002's acceptance (a Compose project name per worktree, no fixed subnets) would let every agent run its own lab.
- **A `needs_human:` frontmatter field** (`decision`, `macos`, `windows`, `person`), shown separately by `board.py`, so tickets waiting on the author are visible at a glance.

## Tickets that probably need the author

| Ticket | Why | Possible split of work |
|---|---|---|
| TP-028 | Certificate decision (in `blocked/`) | Decide when ready |
| TP-043, TP-049 | Library/framework choice is a matter of taste | Agents prepare a comparison, the author picks |
| TP-019, TP-021, TP-023, TP-046 | Need `sudo` on a real Mac and a real network | Agents build and test in the lab; the author runs a short checklist |
| TP-047, TP-048 (Windows part) | No Windows machine available when this was written | Code and cross-compile by agents; testing needs a Windows VM or PC |
| TP-051 | A real person joins without help | The hand-off test is the author's |
| KRN-001, KRN-002 | Releasing go-kernel means pushing a tag | Ask before each push |

## Likely merge-conflict hotspots

| Shared file | Touched by | Possible mitigation |
|---|---|---|
| `go.mod` / `go.sum` | almost every ticket | Merge serially; resolve with `go mod tidy` |
| `cmd/thinkpol` command wiring | TP-004, 011, 016, 022, 038, … | One file per command (set up in TP-001), so new commands don't touch shared code |
| Network map schema | TP-003, then 013, 016, 030, 031, 040 | Merge schema changes one at a time; rebase onto the latest schema before review |
| Lab topology | most lab tickets | Tests declare the nodes they need instead of editing one shared topology |

## Environment notes

- Local Go was 1.24 with `GOTOOLCHAIN=auto`; `go 1.25` in `go.mod` downloads the right toolchain automatically.
- go-kernel is public, so no `GOPRIVATE` or SSH setup is needed to fetch it.
- Linux-only code (network namespaces, netlink, nftables, NFQUEUE) can't be tested on the macOS host; its tests run inside lab containers.
