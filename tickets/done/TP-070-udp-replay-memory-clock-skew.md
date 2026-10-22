---
id: TP-070
title: "udp replay memory vs sender clock skew"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: S
depends_on: []
refs: [C1, C3, C6, docs/design/transports.md#transports]
owner: "glm-tp070"
branch: "tp-070-udp-replay-skew"
---

## Goal
Replay filtering and sender-id memory use consistent clocks so a skewed sender cannot replay after eviction.

## Scope
- `udp/replay.go:110-119` forgets an evicted sender id after `maxClockSkew` on the receiver's clock; `wire.go:232-235` accepts a datagram within `maxClockSkew` of its sealed time on the sender's clock. Remember evicted and retired ids for twice the skew (or equivalent fix).
- `udp/listener.go:264-266`: a late datagram from a dead port can open a new link toward that address.
- `udp/replay.go:172`: a replay refreshes a slot's LRU stamp before the replay check.

## Out of scope
- Supervisor-restart replay window (TP-069).

## Acceptance
- [x] evicted sender ids stay refused long enough relative to sender-clock acceptance
- [x] `TestNineRedialsThenQuietThenOldest` extended with the sender's clock skewed ahead by the allowed skew (passive tap replay cannot open a link and get probe replies)
- [x] a late reordered datagram from a dead port does not open a new link toward that address (`udp/listener.go`) — refined in round 2: only the newest counter opens a link, so a newest in-flight datagram from a dead port opens a link that dies again by DeadAfter (see Notes)
- [x] a replay does not refresh a slot's LRU stamp before the replay check (`udp/replay.go:172`)

## Review findings
Round 1 review (cross-model, 2026-10-15):

- [x] **B1** `deadRemoteHold` locks out a live dialer whose link the exit closed by mistake (`udp/listener.go:289-291`, recorded at `:398`). TP-080's device run 3 shows the exit closing a link with `last_in=4ms` and `last_proof=6.41s`: its probes were lost behind bulk traffic while authenticated data kept arriving every few ms. The client's own link is still up and it keeps sending from the same sender id and port; for 30 s every datagram matches `f.shut` and goes to the camouflage. On the base code the next datagram reopened a link at once; now the client sees no answers for ~6 s or more (its own DeadAfter) and redials — a guaranteed outage replaces an instant recovery, which is what TP-080/084/085 try to shorten. `serverLink.Close` is called for every reason the path layer has (dead-after, wrong space, a self link at `path/node.go:361-363`); the "it gave up on the remote" premise isn't checked. The hold doesn't stop the adversarial case either (an attacker can wait 30 s, or inject from another address). The comment at `listener.go:390-391` is now false. FIX: drop the time-based hold; open a new link only on `v == deliverNewest`, the same rule that moves an existing link's remote.
- [x] **S1** Memory is measured from eviction time, not from when the sender was last seen (`replay.go:92-93`, `:172-173`). An evicted sender that keeps sending hits `has()` → `dropStale` without refreshing `at`: a sender clocked ahead by the skew, sending at T_e+x, has datagrams fresh until T_e+x+10 min, but its id is forgotten at T_e+10 min, so a passive tap can replay in between. FIX: on a `has()` hit, refresh the entry, or (better, see S2) key the memory to the sealed time.
- [x] **S2** The memory uses a monotonic clock while freshness uses the wall clock (`replay.go:124,131`, `listener.go:180`, `router.go:116` versus `wire.go:233`). After NTP steps the receiver's wall clock back by Δ, replays get through in the Δ window. The fake clock advances both together, so no test can see it. FIX (preferred, also fixes S1 and S3): store the newest sealed `o.sent` seen per evicted or retired id, and forget the id once `fresh` would reject that sealed time, using the same arithmetic as `fresh()`.
- [x] **S3** A one-second gap at exactly 2×skew (`replay.go:98,124,131`): `fresh()` truncates to whole seconds, the memory compares nanoseconds. Fixed by S2, or by `senderForget = 2*maxClockSkew + 2*time.Second`.
- [x] **S4** Docs contradict the code: `doc.go:74` ("captured more than five minutes ago is dead everywhere" — it can be fresh for up to 10 min after capture), `doc.go:78-79` likewise; the "Links" section (`doc.go:91-93`) and DESIGN.md don't describe the new behaviour; `doc.go:70` says "Everything else goes to the camouflage, and is counted" — any new drop path must increment a counter; `doc.go:100` says "The Router keeps no replay state", but `router.go:72` calls `admit`.
- [x] **S5** Test gaps: same sender, same port, still alive, after a mistaken close reopens a link at once (the B1 regression); same sender from a new port; a reordered OLDER datagram (not newest) from a dead or old port doesn't open a link; the S2 wall-clock step test replaced by the sealed-time memory fix (see Notes, round 2 S2 caveat); a test at the exact 2×skew boundary (S3).
- [x] **N1** A reordered late datagram from an earlier port (P, after the link moved to Q) still opens a link toward the dead P. The `deliverNewest` rule in B1 covers it.
- [x] **N2** Retired-flow memory now lasts longer. Fine, but say so in doc.go.

Round 3 review (delta, 2026-10-15):

- [x] **R3.1** Refresh tests (`TestAnEvictedSenderKeepsRefreshingItsMemory`, `TestAnEvictedSenderThatKeepsSendingStaysRemembered`) must force `expire()` via a new sender after the clock step and before the replay; without `note()` in `seen()` both must fail.
- [x] **R3.2** `TestTheMemoryExpiresExactlyWhenFreshnessDoes` must use `seen()` and `expire()` on the production path; drop test-only `has()`.
- [x] **R3.3** `TestNineRedialsThenQuietThenOldest` comment: sealed-time memory, not “twice the skew”.
- [x] **R3.4** `doc.go`: withheld-newest-datagram attack; with no link open, opens one toward the attacker until DeadAfter.

## Notes
- **Independent review (2026-10-15):** failure scenario — sender clocked ahead by the allowed skew plus eight redials during an outage lets a passive tap replay a datagram, open a link to the attacker's address, and get probe replies. `TestNineRedialsThenQuietThenOldest` never skewed the sender's clock.
- **Round 2 (2026-10-15):** the dead-remote hold is gone; a link opens only on the current sender's newest counter, so a newest in-flight datagram from a port the app just closed on opens a transient link (it dies again by the path layer's DeadAfter) — accepted: an instant recovery for a live dialer beats a guaranteed 30 s outage, and the hold never stopped the adversarial case anyway. The replay memory (evicted ids, retired credentials) now keeps the newest sealed send time seen from the id and forgets it when the freshness check would reject that time — the same arithmetic, so a wall clock stepped by NTP moves both together. A new `NoLink` counter covers the drop of a datagram no link could take that opens none.
- **Round 2, S2 caveat:** a test that steps the WALL clock independently of monotonic time can't be written with stdlib `time.Time`: a time's monotonic reading (if present) always moves with the wall one under `Add`, and `Sub` falls back to the wall when the reading is stripped — so any injected clock shows a step to both the old `Sub`-based memory and the wall-based freshness check alike. The divergence exists only against the real kernel clock (settime moves REALTIME, not MONOTONIC). The fix removes monotonic time from the memory entirely (it reads only sealed uint32 seconds through `sentFresh`), so the round-1 bug is gone by construction; the S1 and S3 tests pin the new arithmetic. Logged as an inference from the time package's documented behaviour, not something a test can catch.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): acceptance for listener and LRU-stamp bugs
- 2026-10-15 backlog → in-progress — owner: glm-tp070
- 2026-10-15 docs: DESIGN.md's bounded-state bullet and doc.go's receiver rules now say ten minutes (twice the skew), not five — the docs were wrong about the bound, fixed in this branch
- 2026-10-15 in-progress → review — evicted and retired sender ids remembered for 2 × maxClockSkew; nine-redial replay test run with the sender's clock at the full skew; a link closed by the app remembers its remote and refuses to reopen toward it; replay no longer refreshes the LRU stamp; make lint, make test green on a Mac; lab not run (udp unit tests only)
- 2026-10-15 review → has-errors — round 1 review (cross-model): dead-remote hold blocks live dialers; replay memory clock
- 2026-10-15 has-errors → in-progress — round 2: picking the findings up
- 2026-10-15 in-progress → review — round 2: the dead-remote hold is gone, a link opens only on the sender's newest counter (a mistaken close reopens at once while the dialer sends); the replay memory and the retired credentials run on the newest sealed send time seen, by the freshness arithmetic, so an NTP wall step moves both together and an evicted sender that keeps sending stays remembered; NoLink counts the drop of a datagram no link could take; docs (doc.go, DESIGN.md) match; every finding has a test failing on a768152 except S2 (unwritable with stdlib time.Time — see Notes); make lint, make test green on a Mac; lab not run (udp unit tests only)
- 2026-10-15 docs: acceptance box for late datagrams narrowed to reordered ones (approved by orchestrator)
- 2026-10-15 review → has-errors — round 3 review (delta): refresh tests, `has()`, doc and comment nits
- 2026-10-15 has-errors → in-progress — round 3: picking the findings up
- 2026-10-15 in-progress → review — round 3: refresh tests admit a new sender so `expire()` runs before the replay; `TestTheMemoryExpiresExactlyWhenFreshnessDoes` uses `seen()` and `expire()`; `has()` removed; doc.go withheld-newest attack; make lint, make test green on a Mac; lab not run (udp unit tests only)
- 2026-10-15 merged into rewrite (review → done)
