---
id: TP-230
title: "A reality device opens a short TLS connection every ~5 s on the other address family"
milestone: M2
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-230"
branch: "tp-230-reality-tls-every-5s"
---

## Goal
During the censor matrix's reality holds (TP-223's runs, 2026-11-16), device-a opened about 92 short TLS connections to the server's port 443 over IPv4, one every ~5 s, each completing a handshake and closing, while the link itself rode IPv6. A fixed 5-second pattern of short handshakes is a fingerprint a censor on the path can see. Find what opens them (path probing of the other family, a dial loop, a health check) and decide whether it is needed.

## Scope
- Find the code that opens these connections, with evidence from a lab hold.
- Propose to the owner whether to remove or reshape the pattern, or accept it as a residual risk.

## Out of scope
- Any product change before the owner has seen the fix's scope.

## Acceptance
- [ ] The code that opens these connections named in Notes, with the evidence (a capture or the trace from a lab hold).
- [ ] Either the pattern is removed or changed so it no longer forms a fixed short-handshake rhythm, with a lab check that would catch it coming back, or the owner accepts it as a residual risk with a RESIDUAL-RISKS.md row.

## Notes
- Investigation first; the fix's scope goes to the owner before any product change.

### Investigation (2026-11-16, partial: code reading only, no lab evidence yet)

What the code settles:
- The only TLS client a device has is the reality dialer, `internal/dataplane/transport/reality/dialer.go:25` (the listener's `verifyTarget` is the server's, toward its target). Its only caller is the path layer's dial loop, `internal/dataplane/path/link.go:518`, in `startDial` (`link.go:510`). No health check, prober or second client exists on a device: so these connections are path-layer dials.
- One dial loop per dialed neighbor (`Node.Update`, `internal/dataplane/path/node.go:219`, keyed by node id). It dials the neighbor's endpoints in map order; `lab/maps/reality.yaml` lists server-1's IPv4 endpoint first, IPv6 second. A dial that fails, or whose link is never proven, moves to the next endpoint after a backoff of 250 ms doubling to `RedialMax`, **5 s** (`node.go:71`, `link.go:549`, `link.go:557`). A proven link that dies restarts from the first endpoint (IPv4). The 5 s matches the observed rhythm; the agent's `RetryAfter` (`internal/agent/dataplane.go:143`, a failed data-plane start or Apply) is also 5 s and is the other candidate.
- A dial spliced to the target completes the TLS handshake with the target's certificate, then fails with `ErrNotAuthenticated` and closes at once (`dialer.go:74`): exactly "a short TLS connection that completes its handshake and closes". The server dials its target on every accepted connection, authenticated or not (package doc), so the camouflage dials appear either way.

What it doesn't settle: a dial loop that holds a live link waits on it (`link.go:524`) and dials nothing, so one loop can't dial IPv4 every 5 s while it holds the IPv6 link. One of these must be true, and the lab run decides which:
  (a) the loop is in a failure run and the IPv6 connection that carries traffic is a link it never counted as proven (`neighbor.pick` sends on an unproven link, `link.go:57`); or
  (b) something starts a second engine/dial loop every 5 s that dials the first endpoint and is torn down (a data-plane start or Apply retried every `RetryAfter`); or
  (c) IPv4 dials are spliced by the server (unrecognised hello) and the loop's IPv6 link keeps dying and restarting from IPv4 (would show many IPv6 connections too).

Reproduction, ready to run: `make lab-gotest PKG=./lab 'RUN=TestCensorMatrix/^reality/^(off|wireguard-rhythm)'` (no `$` anchors: make expands `$/` to nothing and the run matches no cell). During the 450 s hold, inside the lab's containers: `ss -tni '( dport = :443 )'` in device-a once a second, a capture of TCP 443 SYN/FIN/RST per family on the router, and `thinkpol status` in device-a (its neighbor's links: endpoint, dialed, up). Device-a's info log names the first failed dial of a run (`dial failed` with the error: `the server didn't authenticate` means spliced, `no answer within 6s` means an unproven link) and every `link up` / `link closed`.

Outside the lab: nothing in the dial loop is lab-specific. Any device whose neighbor lists several endpoints (a dual-stack server lists both families) runs the same loop, so (a) and (c) would happen wherever one endpoint keeps failing; whether the IPv4 endpoint fails only because of the lab's topology is for the run to show.

Options (to price once the cause is known):
1. Don't dial other endpoints of a neighbor while a link to it is up, and back a failing endpoint off far past 5 s (minutes, with jitter). Cheap (dial loop only); risk: failover to a dead family's sibling waits on the backoff.
2. Jitter the redial backoff and raise `RedialMax` to minutes for every loop. Cheapest; still a periodic pattern, only slower.
3. Find and remove the second dialer if it is (b): a bug fix, no trade-off.
Recommendation pending the lab evidence; the leaning is 3 if (b), else 1.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 backlog → in-progress, owner: agent-tp-230
- 2026-11-16 investigation (partial): the connections can only come from the path layer's dial loop (path/link.go:518) through the reality dialer; 5 s matches RedialMax (path/node.go:71) or the agent's RetryAfter; which condition holds is open, see Notes. Lab reproduction not done: the lab's machine stopped answering. Handoff: run the reproduction in Notes, then fill in the cause, evidence and recommendation.
