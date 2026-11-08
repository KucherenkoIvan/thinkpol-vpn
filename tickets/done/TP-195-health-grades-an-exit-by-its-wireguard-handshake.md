---
id: TP-195
title: "Health grades an exit by its WireGuard handshake"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-140]
refs: []
owner: "agent-tp-195"
branch: "tp-195-exit-handshake-health"
---

## Goal
Health is not "ok" while a peer the device routes through (an exit, directly or behind a relay) has never completed a WireGuard handshake or has gone silent past a deadline.

## Scope
Today health counts only neighbours (the first hop). Device → entry → exit with the entry up and the exit never answering reads ok, and so does a direct exit whose link is proven but whose handshake never completes. TP-140 recorded this in RESIDUAL-RISKS.md and its Notes.

## Out of scope
None named.

## Acceptance
- [x] a unit test: an exit peer with no handshake past the deadline raises a problem (snake_case code); one that handshakes clears it
- [x] lab: device → relay → exit with the exit's WireGuard blocked shows the problem in `thinkpol status`
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-140's round-1 reviews, 2026-11-07. On the MVP path (orchestrator's call): the tray and daily use read health.
- Proposed follow-up (round-1 review, not built): replace the log parsing with a conn.Bind wrapper around the path.Bind that watches outbound WireGuard messages by type: a type-1 (initiation) sent to a peer's endpoint sets its pending time, a type-2 (response) received from or sent to it clears it. That drops the dependence on wireguard-go's log wording and works with the verbose log off.
- Grading: a chain has one exit (netmap.Chain.Exit), so R1.1's "none of the default chain's exits is live while one is unanswered" is that exit unanswered; "live" isn't computed. If chains get several exits, exitHandshakes needs it.

## Review findings
- [x] R1.1 grading: an exit is unanswered (pending past the deadline), live (a handshake within RejectAfterTime) or neither, computed in one function called from statusWith; down when the default route goes through a chain and none of that chain's exits is live while one is unanswered, any other unanswered exit degraded; table tests; ProblemExitNoHandshake comment and both api-overview files say exactly this
- [x] R1.2 docs say a flag stays until a later handshake completes, even if the device goes idle (wg/doc.go, HandshakePendingSince comment, api-overview-reference.md, api-overview.md, RR48)
- [x] R1.3 a real-wireguard-go test of the responder-side clear (Sending handshake response)
- [x] R1.4 the deadline constant in internal/dataplane, no wg import in agent; test-knob plumbing simplified where natural
- [x] R1.5 wg/doc.go names the three wireguard-go log strings this depends on and the test guarding them
- [x] R1.6 a peer removed, or re-added with another Node, forgets its pending time; tested
- [x] R1.7 no exit_no_handshake while the exit's first hop is down; the deadline restarts when the link returns; tested
- [x] R1.8 nits: handshakeLog → handshakes with a constructor; comment wording (deadline ~30 s to notice a dead session, RR48, api-overview.md:200, dataPlaneProblems); a steady-traffic test over several deadlines stays ok
- [x] R2.1 should-fix, false sticky DOWN: an exit flagged pending whose first hop goes down, WireGuard gives up retrying (~90 s without traffic), the link returns and the device stays idle reads DOWN once UpFor reaches the deadline, with no initiation sent over the restored link. Record each peer's last "Sending handshake initiation" time (PeerStatus) and don't flag an exit whose last initiation is older than its first hop's coming up (flagged while the link stayed up keeps its flag, R1.2); table case and mutation
- [x] R2.2 nit, suspected race: forget(removed) runs before IpcSet removes the peer, so an initiation the old peer logs in between re-creates pending and the re-added peer inherits it; forget again after IpcSet
- [x] R2.3 should-fix: the default rule isn't what carries the traffic no other rule names (`cidr:0.0.0.0/0 -> chain:de`, `cidr:::/0 -> chain:de`, `default -> chain:nl`: nl carries nothing, de everything, de dead reads only degraded). DefaultExit is the exit of the action holding the background (/0) routes, per family; Default()'s comment, ProblemExitNoHandshake's and both api-overview files say so; table case and mutation

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-195
- 2026-11-07 unit tests: TestExitsUnansweredPastTheDeadline, TestAnExitThatNeverHandshakesIsExitNoHandshake, TestHealth (two exit cases), wg TestAnUnansweredHandshakeStaysPendingUntilOneCompletes; mutations, each caught: pending reset on every initiation, a response not clearing pending, `>=` deadline → `>`, the Exit check dropped, all-exits-down graded degraded, the engine's Exit flag always false
- 2026-11-07 `make lint`, `make test` green on 746b0c8; lab TestHealthWithAnExitThatNeverHandshakes passes (device-a → server-1 → server-2, server-2's handshake initiations dropped: `health: down: exit_no_handshake`, then ok once they pass); mutation, caught: the engine's Exit flag always false (no exit_no_handshake within 90 s)
- 2026-11-07 full `make lab-test` green on 8a657d2 (GOFLAGS=-p=2, LAB_P=1, under the CPU lock); not verified: a real device (macOS/Android) showing exit_no_handshake in the tray
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-09 handoff taken over after the previous agent hit a usage limit; its uncommitted R1.1/R1.4 edits kept (checked, committed as d0a3ca5)
- 2026-11-09 R1.1 exitHandshakes (status.go) is the one grading function: an exit unanswered past the deadline counts, and the default rule's exit (rules.Table.Default → RuleStatus.DefaultExit) unanswered is down, any other degraded; a chain has one exit, so "live" isn't computed (Notes). R1.4 ExitHandshakeDeadline in internal/dataplane, agent no longer imports wg; the tuning knob kept, defaulted in RunDataPlane. R1.6 wg forgets a peer's handshakes when Configure removes it or re-adds it with another Node (reset on replace_peers). R1.7 the deadline counts from the later of the first initiation and the first hop's UpFor; no up first hop, no exit_no_handshake. R1.8 handshakeLog → handshakes with newHandshakes; comments and docs (wg/doc.go, device.go, api-overview*.md, RR48) per R1.2, R1.5, R1.8
- 2026-11-09 tests: TestExitsAreGradedByTheirHandshakes (table: default direct + dead chain degraded; default nl dead + de idle down; nl dead + de live down; nl live + de dead degraded; all live ok; first hop down, back for less than and for the deadline; relayed; device peer), TestDefaultIsTheDefaultRulesAction, TestRulesRouteThroughTheChainsExit's DefaultExit, wg TestAPeersInitiationClearsAPendingOne (real wireguard-go, X initiates while A's pending), TestAnUnansweredHandshakeStaysPendingUntilOneCompletes (re-added through another Node starts afresh), TestAnExitThatNeverHandshakesIsExitNoHandshake (stays ok 4 s, four deadlines, under steady traffic)
- 2026-11-09 mutations, each caught: "Sending handshake response" not clearing; forget(removed) dropped; every unanswered exit graded as the default's; the first hop ignored; the deadline not restarted when the link returns; grading by the last handshake's age (steady-traffic phase); the last default rule winning; DefaultExit never set
- 2026-11-09 merged origin/rewrite (stream: core added); `make lint`, `make test` green on a0e16cf
- 2026-11-09 full `make lab-test` green on 86c2a9e (GOFLAGS=-p=2, LAB_P=1, under the CPU lock), TestHealthWithAnExitThatNeverHandshakes included; not verified: a real device showing exit_no_handshake
- 2026-11-09 has-errors → review
- 2026-11-09 delta check: R2.1–R2.3
- 2026-11-09 R2.1 wg records each peer's last initiation (PeerStatus.LastInitiation, through dataplane.PeerStatus); exitHandshakes skips an exit whose last initiation predates its first hop's coming up (status.go). R2.2 Configure forgets removed peers (and resets on replace_peers) again after IpcSet; no deterministic test (the window is inside wireguard-go's IpcSet), left untested. R2.3 rules.Table.Background (each family's /0 action); RuleStatus.DefaultExit → DefaultExits [2] (IPv4, IPv6), the background chains' exits; down if either is unanswered. Docs: Default()'s comment, ProblemExitNoHandshake, Status, wg/doc.go, both api-overview files, RR48
- 2026-11-09 tests: TestExitsAreGradedByTheirHandshakes (+ no initiation since the hop came up → ok; given up while the hop stayed up → down; both families via de, de dead → down; IPv6 via de, de dead → down), TestDefaultExitsCarryTheBackgroundRoutes (dataplane), TestBackgroundIsWhatTakesTheMostAddresses (rules), TestTheLastInitiationMovesWithEachOne (wg). Mutations, each caught: the last-initiation check dropped; DefaultExits from the default rule's action; LastInitiation set only once; Background as the default rule's action
- 2026-11-09 `make lint`, `make test` green (GOFLAGS=-p=2, under the CPU lock); no lab run: only the grading and status changed, not lab-tested behaviour
- 2026-11-09 review → done (merged)
