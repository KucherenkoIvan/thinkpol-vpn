---
id: TP-266
title: "Packages that need no root or namespace run their tests on the host, not in a lab node"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-266"
branch: "tp-266-host-packages"
---

## Goal
The node phase (`labctl gotest ./...`) runs every package's tests in a lab node. packettest and path never need root or a namespace (no test reads `THINKPOL_LAB`), yet each costs a container start and a lab slot on every cold run, for 0–13 s of tests (TP-263). Running such packages as plain host `go test`, cached by Go's own test cache, saves those starts.

## Scope
- Decide per package (build tags or a marker) which need a node; the rest run as host `go test` in `make lab-test`'s node phase or in `make test`, keeping what they prove.
- Candidates on rewrite c4c4b779 (no test file reads `THINKPOL_LAB`, `Geteuid` or a netns; to confirm per package): internal/agent/ipc, internal/agent/logring, internal/agent/worker, internal/dataplane/blobs, internal/dataplane/checksum, internal/dataplane/ifbind, internal/dataplane/packettest, internal/dataplane/path, internal/dataplane/rules, internal/dataplane/transport, internal/dataplane/transport/memory, internal/dataplane/transport/transporttest, internal/dataplane/trusteddir, internal/dataplane/wg, internal/devmap, internal/lists, internal/netmap, internal/shaping, lab/ip.

## Acceptance
- [ ] List of packages moved, with why each needs no node.
- [ ] Node-phase lab starts before/after, in Notes.
- [ ] Every moved package still runs in make lab-test (or make test) and passes.

## Notes

## Log
- 2026-11-19 created in backlog (TP-263)
- 2026-11-19 backlog → in-progress, owner: agent-tp-266
