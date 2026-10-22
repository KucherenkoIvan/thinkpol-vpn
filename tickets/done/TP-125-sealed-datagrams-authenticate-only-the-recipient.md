---
id: TP-125
title: "Decide: sealed datagrams authenticate only the recipient"
milestone: M2
area: transport
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "orchestrator"
branch: "tp-125-sealed-datagrams-decision"
---

## Goal
A recorded decision on the independent design review's point (2026-10-13, section 8) that `udp`'s sealed datagrams authenticate only the recipient, which TP-062 left undecided.

## Scope
- State what the point means for this design: who can produce a datagram the supervisor accepts, what the worker then trusts it for (WireGuard still authenticates the peer), and what an attacker gains (reply addresses, flow cost, fair share).
- Decide: accept (with the reason, and a residual-risks row if anything is left), or a change to the seal (sender authentication) with its cost.
- Write it in DESIGN.md (or the `udp` package doc for the mechanism) and file implementation tickets if any.

## Acceptance
- [x] the decision and its reasons are written down; a residual-risks row exists if anything is accepted

## Notes
- **Decision (owner, 2026-10-23): A, accept.** No signature per datagram.
- **The analysis behind it:**
  - The seal's secret is per link: only the link's two ends hold it, plus the controller that built the map. So a datagram that authenticates proves "one of the two ends", and the sender id inside the seal is a claim.
  - An outsider gets nothing: an unknown connection id is dropped before any decryption, no worker is woken and nothing answers.
  - A replay is dropped, except after a supervisor restart (RR34, TP-069).
  - A holder of one link's secret can, before WireGuard, take that link's reply address (while it keeps sending, if its sender's creation time is later), get probe answers, have frames relayed under a source id the node knows, and spend the listener's decryption, which every space on the node shares. WireGuard still authenticates every peer, so nothing forged gets into the tunnel.
  - A signature per datagram (option B) would not stop a stolen device, which holds the key, nor a copied datagram racing the original. It would add a second public-key layer and about 64 bytes per datagram.
  - The one place verify-without-forge matters is a gatekeeper that verifies for every space: noted in TP-063.
- From TP-077's residual-risks research (2026-10-22). TP-062's Notes: "not among the owner's decisions and isn't written down".

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
- 2026-10-23 backlog → in-progress — owner: orchestrator, branch: tp-125-sealed-datagrams-decision
- 2026-10-23 the decision is in the `udp` package doc (the seal) and RESIDUAL-RISKS.md RR33 (decided); TP-063 carries the gatekeeper's verify-only question; make lint and make test pass
- 2026-10-23 in-progress → review
- 2026-10-23 round 1 (correctness, design: fix first): the decision is in docs/design/transports.md; server-agent.md says verifying is forging for symmetric `udp` (TP-063 decides); RR33 retitled, its holders completed (map builder, section openers, the gatekeeper), its abuse list widened to what the code allows (sender, probe answers, relayed frames), the size-profiling claim replaced by the real costs; the udp doc states the constraint only; TP-063 names the three options (orchestrator)
- 2026-10-23 second opinion: RR33 says what a holder does before WireGuard and what persists (the reply address until 30 s of silence), and the shared listener's decryption (RR38); server-agent.md names the third gatekeeper option (orchestrator)
- 2026-10-23 merged to rewrite (round 1 plus fixes by the orchestrator; correctness checked the final text)
