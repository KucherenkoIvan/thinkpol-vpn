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
- [ ] udp and memory still pass the transport conformance suite and existing udp tests
- [ ] `make lint`, `make test`, `make lab-test` pass
- [ ] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Must land before TP-087 so `reality` does not add a third copy of the admit ladder.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-101-udp-one-receiver-for-admit-ladder
