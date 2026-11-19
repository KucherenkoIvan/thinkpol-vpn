---
id: TP-252
title: "Flaky lab: censord fails to start with 'netlink validate: mismatched sequence'"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-252
branch: tp-252-censord-netlink-seq
---

## Goal
In a full lab on TP-251's branch (2026-11-19, three other labs running) the censor-matrix cell reality × fully-encrypted errored because censord failed to start: "register on queue 100: netlink validate: mismatched sequence in netlink reply"; a targeted re-run of the cell passed. Find which netlink call (nfqueue bind, nftables, conntrack over ctnetlink) gets a reply with a sequence number it didn't send (a shared netlink socket used concurrently? a stale reply from a previous censord run in the same netns? a library bug), and fix the cause.

## Scope
- Reproduce, name which netlink call gets the reply it didn't send and why, and fix the cause.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- Root cause: the call that read a reply it didn't send is go-nfqueue's queue setup, not nftables or ctnetlink, and nothing shares the socket between goroutines. censord's Run installed its queue rule (nftables, `queue num 100`) before `RegisterWithErrorFunc` had set the queue up. That function sends five acked config requests through `netlink.Conn.Execute` on the socket queued packets arrive on: unbind family, bind family, bind queue, copy mode, queue maxlen. Execute takes the next message as the reply and validates its sequence. Once the queue is bound (the third request), a forwarded packet is delivered to that socket as an NFQNL_MSG_PACKET with sequence 0. If it lands before the copy-mode or maxlen ack, Execute reads it as the ack and fails with "netlink validate: mismatched sequence in netlink reply". The lab's message carries none of the "could not unbind/bind" prefixes go-nfqueue puts on the first three requests' errors, so it came from one of the last two, after the bind. Any packet the router forwards in that window will do (a cell's leftover traffic, a retransmission), and load widens the window, hence a flake under three concurrent labs. A table left by an unclean stop opens the same window, since it queues to the same queue number before the new censord sets up.
- Evidence: TestRunStartsUnderTraffic (lab/censor/queue_linux_test.go:299) floods the node's own output, which a rule on the output hook queues, and starts the censor 20 times. On the pre-fix order (4401f608) it failed on start 1 of 20 with "censor: register on queue 205: netlink validate: mismatched sequence in netlink reply", the lab's error word for word.
- Fix (lab/censor/queue_linux.go): `run` (:32) deletes a stale table first (:35). `serveQueue` (:51) takes the rule as `queueRule` and calls it only after register returns (:104), then logs "censor ready". The rule's hook is a parameter (`installQueueRule`, :168): forward in the router, output in the test. Its chain is now `judge`, since `queue` is an nft keyword. Until censord is ready the router forwards uncensored, where before it dropped (no listener on the queue). Lab tests start their traffic after "censor ready", and lab/censor/doc.go says so. No retry and no timeout was added.
- Out of scope: (1) internal/dataplane TestTheFirstInitiationSinceLinkUpIsFromTheNeighborsUpSince failed once in `make test` on d0465389 under load (about 16 load on 6 cores) and once in a targeted `-count 20`. A second `make test` passed. That package doesn't import lab/censor, and no ticket names it yet. (2) At shutdown under traffic censord logs "verdict for packet N: netlink send: ... closed file": go-nfqueue's Close closes the socket before it cancels and waits for the callback, so a verdict in flight fails. The kernel drops those packets when the socket closes, so it's noise only.

## Log
- 2026-11-19 created in backlog (seen in lab runs 2026-11-19)
- 2026-11-19 backlog → in-progress, owner: agent-tp-252
- 2026-11-19 cause: go-nfqueue's acked queue-setup requests read a packet queued after the bind as their ack, because censord installed its queue rule first. Forced repro TestRunStartsUnderTraffic failed start 1 of 20 on 4401f608 with the lab's error. Fix (e42e7599, f0c0f8d6): delete a stale table, bind and set the queue up, then install the rule
- 2026-11-19 runs on d0465389 (merge of rewrite at e7e7435c): lab-gotest ./lab/censor RUN=TestRunStartsUnderTraffic|TestQueuePipeline|TestClearRouter COUNT=20, 20/20 each (20 censor starts under the flood per run, 400 starts in all) with other labs running; lab-gotest ./lab/censor/... pass; lab-gotest ./lab RUN=^TestCensorMatrix/^reality/^(off|fully-encrypted) pass (278 s); make lint green; make test green on the second run (first: the dataplane flake in Notes)
- 2026-11-19 mutations, each failing TestRunStartsUnderTraffic on start 1 with "mismatched sequence in netlink reply": M1 run installs the rule before serveQueue (the old order); M2 run doesn't delete a stale table first; M3 serveQueue calls queueRule before register. Restored after each
- 2026-11-19 full make lab-test on d0465389: 3006 s wall time, exit 2. The one failure, TestM0/underlay=ipv4, never got a lab slot ("no lab slot within 15m24s", other tickets' labs running) and passed in a targeted lab-gotest ./lab RUN=^TestM0 (112 s). The default stream ran over its budget (50m5s > 15m) for the same reason. RESULTS.md assembled from both streams with no error cell (not committed), and no "mismatched sequence" in the run. Not seen: which forwarded packet hit the window in the original lab run (its log doesn't say)
- 2026-11-19 in-progress → review
- 2026-11-19 merged rewrite (175b3535; it changes only lab/censor/doc.go's matrix text there): make lint and make test green on a5087454, lab-gotest ./lab/censor/... pass (cached, the test binary unchanged)
