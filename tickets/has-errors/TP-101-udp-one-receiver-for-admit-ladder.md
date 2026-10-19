---
id: TP-101
title: "udp: one receiver for the authenticate-and-admit ladder"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: []
owner: "agent-glm"
branch: "tp-101-udp-one-receiver-for-admit-ladder"
---

## Goal
The udp transport implements replay policy once: the authenticate-and-admit ladder and retired-sender bookkeeping are not copied again when `reality` lands.

## Scope
- One shared `receiver` (or equivalent) for the ladder `idOf` → lookup → `open` → `fresh` → `senders.admit` → counter, today duplicated in `internal/dataplane/transport/udp/listener.go` (~217–252), `router.go` (~49–82), and `dialer.go` (~106–133).
- One place for retired-sender bookkeeping, today in `listener.go` (~158–189) and `router.go` (~116–137).
- A `transport.Inbox` helper for the queue-fed link end and `Accept`, today copy-pasted between `udp/listener.go` (~78–92) and `memory/memory.go` (~290–304).

## Out of scope
- The `reality` transport itself (TP-087); shaping and conformance behaviour unchanged.
- Removing `SendReporter` or `Buckets` (TP-106).

## Acceptance
- [x] udp and memory still pass the transport conformance suite and existing udp tests
- [x] `make lint`, `make test`, `make lab-test` pass
- [x] no behaviour change: existing tests pass unchanged, or each changed test says why

## Review findings
- [x] R2.1 Close order: udp `Listener.Close` and memory `Listener.Close` close the accept Inbox BEFORE `l.done`, so a closing listener never hands out a link from Accept. Better: the Inbox is the listener's lifecycle — drop the listeners' own done/closeOnce/closed() and use the inbox's (export `Inbox.Closed()`); memory `end.closed()` uses it too.
- [x] R2.2 Inbox API in the port: `Queue()` returns `chan<- T`; `Recv` returns the close cause (`i.closeErr`), like `ReadPacket`; `Err()` is safe before Close (nil until closed); align `ReadPacket`'s close race with `Recv`'s (or narrow the type doc). Rename the package-level `ReadPacket` helper to `ReadPacketFrom`. Links hold the inbox as a named field (in `*transport.Inbox[[]byte]`), not embedded, in udp `serverLink` and memory `end`.
- [x] R2.3 Move `idOf` + the unauthenticated counter into the receiver's admit, so the first rung isn't copied three times (the dialer keeps its recognises check).
- [x] R2.4 Remove the dead `flow.senders` field and its stale comment; `listener_test.go` ~664 reads the history the listener actually uses (say why the test changed).
- [x] R2.5 Names: `senderTable` → `senderHistories` (fields `histories`), `receiver` → `admitLadder` (or a name that says it runs the checks and counts drops), `admitWith` → `admitOne`, `sync` → `follow`, `history` → `historyOf`; fix receiver.go ~12's comment; move the embedded ladder above `mu` in Router; router.go ~61's comment.
- [x] R2.6 Allocation: `receiver.go` ~30 `table.history(string(e.link.Verifier))` may allocate per datagram with a valid connection id, before AEAD. Measure (testing.AllocsPerRun or -gcflags=-m); if it allocates, avoid it (look up without converting, as the old code's direct map index did) and keep a test that pins zero allocations on the hot path.
- [x] R2.7 Tests the old suites lacked (a wrong refactor would have passed): the dialer's drop paths — replay a captured down datagram to the dialer → Replayed; a stale-timestamp datagram → StaleTimestamp; an older sender → StaleSender (assert the dial link's Counters()); the router's older-sender → Stale verdict, and its Unauthenticated/Replayed/StaleSender counters; Inbox: Close unblocks a waiting Recv; Close(cause) reaches both Recv and ReadPacketFrom (errors.Is); an item racing Close. Drop inbox_test.go's useless time.Sleep; assert errors.Is(err, context.Canceled).
- [x] R2.8 Ticket Notes: correct the claim that reality won't copy the ladder: receiver/senderHistories are udp's; reality reuses transport.Inbox for Accept and needs its own token replay cache (DESIGN "Bounded state"); the five-minute skew (udp/wire.go maxClockSkew) and the wrap-safe sentFresh are what reality would copy — TP-087 should move them to the port first (add that to TP-087's Notes with a Log line).
- [ ] R3.1 `Inbox.Err()`: safe at any time — `select { case <-i.done: return i.closeErr; default: return nil }`, doc says it returns nil before the close; replace the `select { case <-x.Done(): return x.Err(); default: }` copies (udp listener.go WritePacket ×2, memory end.WritePacket) with `if err := x.Err(); err != nil { return err }`.
- [ ] R3.2 The links' inbox field is `in *transport.Inbox[[]byte]` (unexported, named for its role), not `Inbox`, in udp `serverLink` and memory `end`; every use updated.
- [ ] R3.3 `ReadPacketFrom` builds on `Recv(context.Background())` instead of copying its close-race logic.
- [ ] R3.4 A test that really races an item against Close, for both Recv and ReadPacketFrom: sender goroutine sending until closed, closer goroutine (runtime.Gosched then Close(cause)), reader reading until an error that must be errors.Is(err, cause), then the close is sticky (16 more reads all return the cause); 200 iterations; runs under -race. Rename TestInboxCloseUnblocksAWaitingRecv to what it proves.
- [ ] R3.5 A second concurrent Close waits for the first to finish (as closeOnce.Do did): udp Listener.Close and memory Listener.Close; test: two concurrent Closes on a memory listener, then Listen on the same address succeeds.
- [ ] R3.6 Docs: TP-101 Notes on where the ladder runs and where the dialer keeps its own id check; dialer_test.go's comment ("the ladder from the open on"); admitLadder's type doc lists the connection-id rung and says the lock once; historyOf's comment on why `m[string(b)]` allocates nothing.
- [ ] R3.7 Nits: receiver.go/receiver_test.go → admit.go/admit_test.go with receiver `a`; keep one of Inbox.Closed/closed; inline memory end.closed(); blank line between admitLadder and mu in Router; listener_test.go drop the comment clause about the removed flow field; the zero-alloc test also measures the delivered path (a new counter admitted each run).

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Must land before TP-087, with the claims corrected (round 2): `reality`
does NOT reuse the admit ladder or the sender histories — those are udp's —
and needs its own token replay cache (DESIGN "Bounded state"). What reality
DOES reuse from here is `transport.Inbox`, for its Accept queue. What
reality WOULD copy is the five-minute skew window (`maxClockSkew`,
udp/wire.go) and the wrap-safe `sentFresh`: TP-087 should move them to the
port first (its Notes say so).

What the consolidation is: `transport.Inbox` (new, generic) is the queue-fed
link end both transports hold and the accept queue both listeners own; the
Accept select is `Inbox.Recv`. In udp, `admitLadder` runs the ladder's
checked half (open → fresh → senders.admit → the turn-away counters) for the
listener, the router and the dialer, and `senderHistories` owns the
per-secret sender histories with the retired-sender bookkeeping for the
listener and the router. `inbox_test.go` is new coverage.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-101-udp-one-receiver-for-admit-ladder
- 2026-10-19 in-progress → review — make lint, make test and a full make lab-test (lab plus every package in a lab node) pass at f3a021e; the conformance suite and both transports' tests pass unchanged, so nothing was left unverified
- 2026-10-19 review → has-errors — review round 2: R2.1–R2.8 in ## Review findings
- 2026-10-19 has-errors → in-progress — picking up R2.1–R2.8
- 2026-10-19 R2.1–R2.8 done — the inbox is the listeners' lifecycle and the ladder's first rung lives in admit, allocation-free on the hot path (7abdea2); Notes corrected, TP-087 told to move the skew window to the port first (7609235); make lint, make test, go test -race ./internal/dataplane/transport/... and a full make lab-test (lab plus every package in a lab node, LAB_P=1, exit 0) pass at 6c24bea
- 2026-10-19 in-progress → review — review round 2 closed: all eight findings re-checked against the code, nothing security-relevant changed since 7abdea2; lint, unit, race and the full lab run pass at e92c90a
- 2026-10-19 review → has-errors — review round 3: R3.1–R3.7 in ## Review findings
