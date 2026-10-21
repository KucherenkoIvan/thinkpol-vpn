---
id: TP-120
title: "Flake sweep: tests that fail under load"
milestone: M2
area: tests
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-120"
branch: "tp-120-flake-sweep"
---

## Goal
A red `make test` or `make lab-test` means a real defect. Every test seen failing once under load and passing on a rerun is made deterministic, or its failure is shown to be a product bug and fixed or filed.

## Scope
Seen on 2026-10-21 with several agents running tests and labs at once (each passed alone and on the rerun):
- `internal/dataplane/blobs` `TestATricklingPeerIsAbandoned` (unit): `Abandoned:7` instead of 1. Under CPU load the good peer also misses the ~0.3 s rate window (`MinRate 1<<20`, `DialTimeout 300ms`) and is abandoned. Assert what the test means (the trickling peer abandoned, the good one fetched), or give the good peer headroom that load can't eat.
- lab `TestTwoSpacesShareAListener`: "no reply for a dialer".
- lab `TestSwitchesPathWhenTheRelayCloses/datagram` (`internal/dataplane/path`).
- earlier ones to re-check: the TP-113 Log's `transporttest` ShapingRefused (keep the line next time), and any other test the recall notes tagged `kind:flake` list.
For each: reproduce under load (e.g. `-count` with `-p` raised, `stress`-style parallel runs, or a CPU hog alongside), find the cause, fix the test (or the code if the code is wrong), and show it holds (N runs under the same load).

## Acceptance
- [ ] each listed test: cause in the Log, fix, and a loaded repeat run that passed (count and load stated)
- [ ] a product bug found this way is fixed here if small, else filed
- [ ] `make lint`, `make test`, `make lab-test` pass

## Log
- 2026-10-21 created in backlog (flakes seen during TP-112, TP-102 and TP-116 runs)
- 2026-10-21 backlog → in-progress — owner: agent-tp-120, branch: tp-120-flake-sweep
