---
id: TP-267
title: "A lab waits ~25 s between getting its slot and asking for the subnet lock"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-262"
branch: "tp-262-faster-lab-start"
---

## Goal
In two of TP-263's runs (2026-11-19), 25–26 s passed between a lab getting its slot and asking for the subnet lock (`THINKPOL_LAB_TIMELINE`: routetable after the change, packettest before). Every lab start pays that gap while holding a slot other labs wait for.

## Scope
- Find what runs in that gap (image build check, binary prepare, compose file render, docker info).
- Remove it, or move it before the slot is taken.

## Acceptance
- [x] The gap explained with a timeline.
- [x] The gap under 2 s, or why it can't be.

## Notes
Worked in TP-262's branch (tp-262-faster-lab-start), whose timeline now breaks a lab's start into steps (`start`, `subnet-read`, `down` lines).

**What the gap was.** Between the slot and the lock request a lab ran `usedSubnets`: `docker network ls` and an inspect of every network on the daemon, to keep its subnets clear of everyone's. Under load the daemon answers network reads behind every network it is creating or removing. The old code also fell back to one `docker network inspect` per network whenever one network vanished between the list and the inspect, which happens all the time while other labs come and go. Before (TP-262's baseline at 49693be1; times UTC, project shortened):

```
07:00:07.308 slot-wait 1m3.168s ok tplab-…-gotest-1b3fe6
07:01:10.477 start 36.928s create 36.348s inspect 161ms bridges 118ms seal 301ms nodes 1 networks 1 attempts 1 ok tplab-…-gotest-1b3fe6
07:01:36.624 lock-wait 0s lock 07:01:36.624-07:01:36.625 (0s) up 07:01:36.627-07:01:46.825 (10.198s) attempt 1 ok tplab-…-gotest-1b3fe6
```

The slot came at 07:01:10.477 and the lock was asked for at 07:01:36.624: 26.1 s of subnet read. Across the baseline's 30 measured starts the gap had a median of 0.09 s for 1 node, 2.6 s for 4 nodes and 1.0 s for 7 nodes, and a max of 34 s, 37 s and 49 s.

**The fix.** The read happens before the slot wait (`up`, noted as `subnet-read`). The first try reserves against it plus the live reservations, which cover every lab of the host's slots started since. A try after a Docker overlap reads again, on a read that began after the overlap. The read itself is one inspect per chunk of 4 networks, all chunks at once, taking the CLI's output for the networks it found, and lab starts of one process that ask while a read runs share it. After (1bfbe69c):

```
09:02:42.611 subnet-read 3.423s ok tplab-…-upstre-92886a
09:02:46.034 slot-wait 1.755s ok tplab-…-upstre-92886a
09:02:47.789 lock-wait 0s lock 09:02:47.789-09:02:47.790 (1ms) up 09:02:47.791-09:04:24.936 (1m37.145s) attempt 1 ok tplab-…-upstre-92886a
09:02:47.789 start 1m41.739s create 1m37.147s inspect 2.03s bridges 718ms seal 1.844s nodes 7 networks 3 attempts 1 ok tplab-…-upstre-92886a
```

The slot to lock gap was 0.00 s in all 30 measured starts, against a baseline max of 49 s. The read, now before the slot, had a median of 0.14 s, 0.20 s and 2.5 s (max 1.4 s, 4.0 s and 5.0 s) for 1, 4 and 7 nodes.

Full lab on 289bd442 (another full lab at the same time): slot → lock 0.00 s in all 111 starts; the read before the slot 0.5–3.3 s median, 10.6 s max.

## Log
- 2026-11-19 created in backlog (TP-263)
- 2026-11-19 backlog → in-progress, owner: agent-tp-262 (folded into TP-262 by the orchestrator: the gap is part of a lab's start; moves with TP-262 through review)
- 2026-11-19 done in TP-262's branch: the gap was the read of the daemon's subnets (inspect of every network, one by one when one vanished); now read before the slot (chunked, shared), first try reserves against it; slot → lock 0.00 s in 30/30 measured starts and 111/111 in the full lab on 289bd442; unit tests and mutations in TP-262's Log
- 2026-11-19 in-progress → review (with TP-262)
- 2026-11-19 review round 1 (with TP-262): boxes ticked from this branch's evidence (timeline above, 30/30 measured starts and the full lab's 111); R1.2's fresh read for a full pool is in TP-262's Log; moves to done with TP-262
