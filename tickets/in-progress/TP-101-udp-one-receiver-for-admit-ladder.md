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
- [ ] R2.1 Close order: udp `Listener.Close` and memory `Listener.Close` close the accept Inbox BEFORE `l.done`, so a closing listener never hands out a link from Accept. Better: the Inbox is the listener's lifecycle — drop the listeners' own done/closeOnce/closed() and use the inbox's (export `Inbox.Closed()`); memory `end.closed()` uses it too.
- [ ] R2.2 Inbox API in the port: `Queue()` returns `chan<- T`; `Recv` returns the close cause (`i.closeErr`), like `ReadPacket`; `Err()` is safe before Close (nil until closed); align `ReadPacket`'s close race with `Recv`'s (or narrow the type doc). Rename the package-level `ReadPacket` helper to `ReadPacketFrom`. Links hold the inbox as a named field (in `*transport.Inbox[[]byte]`), not embedded, in udp `serverLink` and memory `end`.
- [ ] R2.3 Move `idOf` + the unauthenticated counter into the receiver's admit, so the first rung isn't copied three times (the dialer keeps its recognises check).
- [ ] R2.4 Remove the dead `flow.senders` field and its stale comment; `listener_test.go` ~664 reads the history the listener actually uses (say why the test changed).
- [ ] R2.5 Names: `senderTable` → `senderHistories` (fields `histories`), `receiver` → `admitLadder` (or a name that says it runs the checks and counts drops), `admitWith` → `admitOne`, `sync` → `follow`, `history` → `historyOf`; fix receiver.go ~12's comment; move the embedded ladder above `mu` in Router; router.go ~61's comment.
- [ ] R2.6 Allocation: `receiver.go` ~30 `table.history(string(e.link.Verifier))` may allocate per datagram with a valid connection id, before AEAD. Measure (testing.AllocsPerRun or -gcflags=-m); if it allocates, avoid it (look up without converting, as the old code's direct map index did) and keep a test that pins zero allocations on the hot path.
- [ ] R2.7 Tests the old suites lacked (a wrong refactor would have passed): the dialer's drop paths — replay a captured down datagram to the dialer → Replayed; a stale-timestamp datagram → StaleTimestamp; an older sender → StaleSender (assert the dial link's Counters()); the router's older-sender → Stale verdict, and its Unauthenticated/Replayed/StaleSender counters; Inbox: Close unblocks a waiting Recv; Close(cause) reaches both Recv and ReadPacketFrom (errors.Is); an item racing Close. Drop inbox_test.go's useless time.Sleep; assert errors.Is(err, context.Canceled).
- [ ] R2.8 Ticket Notes: correct the claim that reality won't copy the ladder: receiver/senderHistories are udp's; reality reuses transport.Inbox for Accept and needs its own token replay cache (DESIGN "Bounded state"); the five-minute skew (udp/wire.go maxClockSkew) and the wrap-safe sentFresh are what reality would copy — TP-087 should move them to the port first (add that to TP-087's Notes with a Log line).

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Must land before TP-087 so `reality` does not add a third copy of the admit ladder.

What the consolidation is: `transport.Inbox` (new, generic) is the queue-fed
link end both transports embed and the accept queue both listeners own; the
Accept select is `Inbox.Recv`. In udp, `receiver` runs the ladder's checked
half (open → fresh → senders.admit → the turn-away counters) for the
listener, the router and the dialer, and `senderTable` owns the per-secret
sender histories with the retired-sender bookkeeping for the listener and
the router. No existing test changed; `inbox_test.go` is new coverage.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-101-udp-one-receiver-for-admit-ladder
- 2026-10-19 in-progress → review — make lint, make test and a full make lab-test (lab plus every package in a lab node) pass at f3a021e; the conformance suite and both transports' tests pass unchanged, so nothing was left unverified
- 2026-10-19 review → has-errors — review round 2: R2.1–R2.8 in ## Review findings
- 2026-10-19 has-errors → in-progress — picking up R2.1–R2.8
