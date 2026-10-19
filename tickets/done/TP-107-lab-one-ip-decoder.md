---
id: TP-107
title: "lab: one IP decoder"
milestone: M3
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
owner: "agent-glm"
branch: "tp-107-lab-one-ip-decoder"
---

## Goal
Lab packet parsing shares one IP decoder instead of two parallel implementations.

## Scope
- Unify `lab/pcap.go` `decodeIP` (~152) and `lab/censor/packet.go` `decodePacket` (~66) into a single helper both call.
- Optionally reduce duplicated process-wide registries with separate mutexes where the merge is straightforward.

## Out of scope
- Changing censor verdict semantics or matrix scoring.
- Lab topology or harness redesign.

## Acceptance
- [x] lab and censor tests that decode packets pass unchanged or note why they changed — `TestPcapStreamDecodesSLL2`, `TestDecodePacket`, `TestDecodePacketIPv6ThroughExtensions`, `TestIsFragment` pass without edits; the shared decoder's own cases live in `lab/ip/ip_test.go`
- [x] `make lint`, `make test`, `make lab-test` pass — lint and test clean at 2f1497f; `make lab-test` (GOFLAGS=-p=4 LAB_P=1) exit 0, 35 packages ok, run 2026-10-19

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

Process-wide registries with their own mutexes in `lab/` (2026-10-19): `prepared`/`preparedMu` (prepare.go, built image and binaries by checkout), `buildLocks`/`buildLocksMu` (prepare.go, one build mutex per output), `claimed`/`claimedMu` (lab.go, lab numbering per project), `slots`/`slotsMu` (hostlock.go, lab slots this process holds), `passives` and `actives` (censor/config.go, sharing one `registryMu`). No two are the same thing — each guards a distinct resource — so none were folded; the censor's two already share their mutex.
- `isFragment` (censor/packet.go) keeps its own extension-header walk: it must flag fragments `ip.Decode` rejects as malformed, or they would reach the queue's Accept path.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-107-lab-one-ip-decoder
- 2026-10-19 in-progress → review — one decoder in lab/ip (2f1497f); registries listed under Notes, no fold applied; nothing left unverified, all runs on this branch
- 2026-10-19 review round 1: all three reviewers: merge; the orchestrator applied their items: ip.Header is ip.Packet (Bytes, LaterFragment, whose zero value is right), locals no longer shadow the ip package, the tests assert ok and cover a first fragment with MF and short IPv4/IPv6 packets, Notes say why isFragment keeps its own walk; make lint, make test, make lab-test LAB_P=1 green (make's own exit 0, 35 in-node packages)
- 2026-10-19 merged into rewrite
