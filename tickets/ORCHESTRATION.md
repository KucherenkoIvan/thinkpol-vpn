# Orchestration notes

Suggestions for running several tickets at once, written down while the board was set up (2026-10-10). **None of this is a rule**, except the [Decisions](#decisions-2026-10-10) section at the end: the board's rules are in [README.md](README.md), and the decisions below are rules for how the board is run. Treat the rest as a starting point, and change or drop anything that doesn't hold up in practice.

## Parallelism

`python3 tickets/board.py --waves` groups unfinished tickets by dependency depth: everything in one wave can run in parallel once the earlier waves are done. When the board was created there were 14 waves, 3–6 tickets wide. Parallelism shortens each wave, but the waves still come one after another.

The board's WIP limit (4) is conservative: a typical dev machine could probably take 4–5 agents at once. The lab is the likelier bottleneck (see below).

## A possible loop

Superseded by the flow in [Decisions](#decisions-2026-10-10); kept for context.

1. Pick ready tickets (`board.py` lists them), up to the WIP limit.
2. One agent per ticket, each in its own git worktree on the ticket's branch.
3. When an agent moves its ticket to `review/`, an adversarial reviewer agent tries to break the change; findings send it to `has-errors/`.
4. Merge into `rewrite` one ticket at a time, rebasing the next one first; move the ticket to `done/` in the same commit.

## Suggested changes to tickets

Both applied on 2026-10-10:

- **Applied: lab isolation per worktree (TP-002).** As written, two lab runs at once would collide on container names and networks. Adding "lab runs are isolated per worktree" to TP-002's acceptance (a Compose project name per worktree, no fixed subnets) would let every agent run its own lab.
- **Applied: a `needs_human:` frontmatter field** (`decision`, `macos`, `windows`, `person`), shown separately by `board.py`, so tickets waiting on the author are visible at a glance.

## Tickets that probably need the author

Now recorded as `needs_human` on the tickets themselves; `board.py` lists them.

| Ticket | Why | Possible split of work |
|---|---|---|
| TP-028 | Certificate decision | Resolved 2026-10-10 (see Decisions); the ACME source is TP-052, blocked until there is a domain |
| TP-043, TP-049 | Library/framework choice is a matter of taste | Agents prepare a comparison, the author picks |
| TP-019, TP-021, TP-023, TP-046 | Need `sudo` on a real Mac and a real network | Agents build and test in the lab; the author runs a short checklist |
| TP-047, TP-048 (Windows part) | No Windows machine available when this was written | Code and cross-compile by agents; testing needs a Windows VM or PC |
| TP-051 | A real person joins without help | The hand-off test is the author's |
| KRN-001, KRN-002 | Releasing go-kernel means pushing a tag | Minor tags may be pushed without asking once review passes (see Decisions) |

## Likely merge-conflict hotspots

| Shared file | Touched by | Possible mitigation |
|---|---|---|
| `go.mod` / `go.sum` | almost every ticket | Merge serially; resolve with `go mod tidy` |
| `cmd/thinkpol` command wiring | TP-004, 011, 016, 022, 038, … | One file per command (set up in TP-001), so new commands don't touch shared code |
| Network map schema | TP-003, then 013, 016, 030, 031, 040 | Merge schema changes one at a time; rebase onto the latest schema before review |
| Lab topology | most lab tickets | Tests declare the nodes they need instead of editing one shared topology |

## Environment notes

- With `GOTOOLCHAIN=auto`, an older local Go downloads the toolchain `go.mod` asks for automatically.
- go-kernel is public, so no `GOPRIVATE` or SSH setup is needed to fetch it.
- Linux-only code (network namespaces, netlink, nftables, NFQUEUE) can't be tested on the macOS host; its tests run inside lab containers.

## Decisions (2026-10-10)

Made by the project owner and the orchestrator. These are rules for running this board.

- **Push everything.** The `rewrite` branch and every ticket branch are pushed to origin. Ticket moves and agent notes are history worth keeping.
- **One worktree per ticket.** Each ticket is worked in its own git worktree at `../.worktrees/<repo>/<branch>`, relative to the main checkout. Ticket moves (`git mv` + Log line) happen on the ticket branch; the branch's first commit is the backlog → in-progress move. The main checkout on `rewrite` is reserved for board ops and serial merges.
- **Flow.** Implementer → `review/` → three reviewer agents (one adversarial, for correctness; one for architecture and style; and since 2026-10-16 a second opinion on the whole implementation from another model family) → either `has-errors/` with the findings written into the ticket, or a merge into `rewrite` that moves the ticket to `done/` in the merge commit.
- **go-kernel tags.** Minor tags for `KRN-` tickets may be pushed without asking, after review passes.
- **TP-028 certificate.** The owner has no domain and no valid certificate. The `tls` server certificate comes from a pluggable certificate source port; the first adapter is self-signed and pinned by the client, used in the lab and tests. A prober sees a self-signed certificate: a known weakness that the lab matrix shows honestly. ACME with a real domain is TP-052, blocked until the owner has a domain and a registrar.
- **Host safety.** Never change the macOS host's network stack (routes, interfaces, DNS, pf, sysctls). Linux networking code runs only inside lab containers.
- **`needs_human`.** Tickets that need the author carry `needs_human: decision | macos | windows | person` (see [README.md](README.md#ticket-files)). For `decision`, agents prepare a comparison and the author picks. For `macos`, `windows` and `person`, agents build and test everything possible in the lab, then hand the author a short checklist.
- **WIP limit raised to 4 (2026-10-10).** Lab runs are isolated per worktree, so the lab is no longer the bottleneck; tickets in `review/` or `has-errors/` don't count.

## Decisions (2026-10-15)

Made by the project owner following an independent review.

- For `needs_human: macos` or `windows` tickets, the real-device run happens after review round 1, not after the lab rounds; the device-test kit is built alongside the implementation.
- ~~At most 3 review → fix rounds per ticket; beyond that, split the rest into a new ticket.~~ Replaced 2026-10-19 by the owner: a ticket keeps its review → fix rounds until its reviewers find nothing worth fixing; what's left goes to a new ticket only when it is outside the ticket's scope. After round 5 the orchestrator asks the owner whether to go on.
- Decisions go into the design file for their topic, under `docs/design/` (DESIGN.md indexes them); tickets carry pointers, not accreted design.
- Security-sensitive code written by one model family gets a second-opinion review from a different family.
- Merge order for the in-flight M1 branches: tp-021 before tp-019; tp-019 absorbs the conflict.
- Critical path after M1: agent-layer refactor part 1 (TP-075), with the Reality evaluation (TP-064) and the censor framework (TP-024) running alongside it; then service install (TP-046), then the macOS/Linux kill switch (TP-048); then the `reality` transport (TP-087) and the censor modules (TP-025, TP-026, TP-032) after TP-064. Daily use starts after M2.
- **REALITY is the M2 disguised transport** (after the TP-064 findings): thinkpol implements REALITY's handshake for client → entry links (TP-087, TP-088); our own `tls` (TP-028) moves to after the MVP. Reuse over rewrite where licences allow: uTLS (BSD-3) is imported; XTLS/REALITY and Xray-core (MPL-2.0) may be unmodified Go module dependencies, never copied into the tree under MIT; TP-087 decides between depending on XTLS/REALITY's server and reimplementing it. Stock VLESS clients and servers are not supported. See PRD "Decisions".
- UX design round after the mechanics: once the core transports and data plane are built, user-facing flows (invites, the admin panel and its canvas, the tray app) get a fresh design round, informed by the technical limits found and by experience from building. Until then UX details in tickets are provisional.

## Device testing (2026-10-16)

Made by the project owner after TP-078's device-test kit grew to about three times the size of the product change it tested, without having run once.

- **Record, don't judge.** Device scripts do a step and save evidence: `thinkpol diag` (TP-091), a capture, the agent's log and timestamps. An agent judges the evidence after the run. Judgement that recurs becomes a Go test over recorded fixtures or a lab test, never device-script logic.
- **Budget.** A ticket's device tooling must not be bigger than the ticket's own change. If a check needs more, it's a product diagnostic or a lab test.
- **Lighter process for tooling:** one review round, a fresh agent per round with a handoff note, and safety (restore, dead-man, no lasting host changes) as a small frozen core kept apart from the checks.

## Consolidation phase (2026-10-18)

Made by the project owner after a design and code-quality review of `rewrite` at M1 (2fa1191). The code is sound, but the data plane's ports are owned by its adapters, the composition root sits in `internal/agent`, and several security-relevant paths are written two or three times. Nearly every M2 feature would land in that code and add another copy, so the restructuring comes first.

- **Order.** TP-098 and TP-099 finish, then TP-100 (faster lab). Then the phase, in waves:
  - wave 0: TP-106, TP-108, TP-105 (TP-106 before TP-101: both touch `transport`);
  - wave 1, in parallel: TP-075, TP-101, TP-103, TP-104, TP-107;
  - wave 2, after TP-075: TP-109 and TP-110;
  - wave 3: TP-083 and TP-102. Whichever lands last adds the `funlen` gate.
- **No feature tickets start until the phase ends.** Afterwards come TP-095 (it edits code TP-102 restructures) and TP-077 (the packages are about to move).
- **Done when:** TP-109's depguard rule passes, `funlen` is on, no test-only globals in the production build, each duplicated security path has one implementation, and a full lab run takes about 3 minutes. The phase touches macOS code (TP-102, TP-108, TP-109), so it also ends with one run of the macOS device checklist by the owner.
- Refactors change no behaviour: existing tests pass unchanged, or each changed test says why.

## Pre-M2 phase (2026-10-24)

Made by the project owner after the macOS device run of the consolidation phase.

- **Why.** The consolidation phase is a net improvement, and its macOS device run (2026-10-24) found no regression. But health and the guard don't always tell the truth: health said ok when no exit was ever reached, a boot crash left no trace, and pfctl output the guard misreads or may never get. M2's disguise and kill-switch work rests on both, so these come first.
- **Order, in waves:**
  - wave 0: a full `make lab-test` on `rewrite` (red means fix first); TP-121; TP-139.
    - TP-139's overview also covers the surface that TP-111, TP-141, TP-133 and TP-140 plan to add.
    - The owner's session is held early, and its verdicts go into those tickets before they start.
  - wave 1: parallel lanes, at most 4 implementers at a time. Each lane owns separate files.
    - Guard: TP-138 → TP-127 → TP-129 → TP-137 (the same two pf files).
    - Agent: TP-141 → TP-133 → TP-140, then TP-111. Starts only after the owner's TP-139 session.
    - macOS: TP-094, TP-124, TP-135.
    - Hygiene: TP-145, after TP-141 touches the config.
    - Harness: TP-082 round 6 (one fix round, then a correctness-only re-check), on its own branch.
  - wave 2: a full lab-test on the result. Then kit fixes and a runbook in the owner's format (navigation table, one linear path, Do / What happens / Expect, every command in a code block). Then the owner runs TP-144, with TP-082's first run folded in if it is ready. Analysis only afterwards.
  - wave 3: TP-142 and TP-143 from the re-run's results; TP-082 merges if its harness passed.
- **Done when:** every ticket above is in done; the lab is green; TP-144 has no FAIL or INCONCLUSIVE left; RESIDUAL-RISKS.md RR12 matches what macOS shows. Then the orchestrator brings the M2 lane plan (lanes, package ownership, merge order, review and quota budget) for the owner's approval.
- **Owner decisions recorded 2026-10-24:**
  - A crash trace is kept on devices only: one root-only file, read before each start overwrites it. Servers and entry nodes keep no disk logs (TP-141 amends PRD S2).
  - TP-046's hook-retry box is closed by accepting the fake-pfctl tests.
  - TP-111 keeps its 2026-10-18 decisions.
- **No M2 feature ticket starts until this phase ends.**

## Code health between milestones (2026-10-18)

- **At every milestone tag,** the owner holds a code-health review session. The orchestrator brings a factual brief: lab suite time, lint gates, the longest functions, code that exists in more than one copy, and the code the next milestone's tickets will touch. The session's findings come to the orchestrator, who files them; what the next milestone needs first becomes a consolidation phase before its features start.
- **Refactors that touch macOS or Windows code** end with a run of that platform's device checklist; the lab covers Linux only.

## M2 order (2026-10-22)

Made by the project owner at the end of the consolidation phase.

- **Install and diagnostics first:** service install (TP-046) and `thinkpol diag` (TP-091). Then the disguised transport (TP-087, `reality`) and the censor lab (TP-089, then TP-025, TP-026, TP-032).
- **Iterate until proven to work.** Each lane lands in small slices, each shown working in the lab before the next starts. A device run takes the owner's time, so it happens once per ticket, at its end, after review round 1 (Decisions, 2026-10-15), unless a slice can't be shown working without one.
- **Device harness (TP-082):** design first. The owner reviews the design before any prototype.

## Design documents (2026-10-22)

- DESIGN.md is the entry point and index; the design files under `docs/design/` hold the model, invariants and decisions by topic, each under 50 KB. Mechanism lives in package docs, residuals in RESIDUAL-RISKS.md.
- **When a design file would pass 50 KB, split it by subtopic** into its own file, and index the new file from DESIGN.md (TP-131).
