---
id: TP-219
title: "The empty-file window on resolv.conf's in-place fallback"
milestone: M3
area: dataplane/dns
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR63, R4]
owner: ""
branch: ""
---

## Goal
Where /etc/resolv.conf can't be renamed over (a bind mount, as in containers), a resolver reading it while the node rewrites it never finds it empty, or the residual is decided and RR63 says which.

## Scope
- The fallback today (internal/dataplane/dns/resolvconf.go, writeFile → writeInPlace, used on EBUSY or EXDEV by the take-over, the take-backs, Update and Restore through putBackOriginal) opens the file with O_TRUNC, then writes. A glibc or musl resolver that reads it between the two finds no nameserver: it asks 127.0.0.1 and has no search domain. Each retry of a rewrite that failed partway truncates the file again.
- Choose between: (a) writing without O_TRUNC, then ftruncate to the new length: no empty file, but between the write and the ftruncate a shorter content is followed by the old content's tail, which a reader takes as more lines (stale nameservers, a cut line); (b) keeping the truncation and narrowing the window; (c) something else that holds on a bind mount (the mount can't be renamed over, and the node can't change the mount). Say in the package doc which, and why.
- Keep the partial-write rules (failedWrite, ownPartial, the held original) right for the chosen write: a failure partway must still never lose the original.
- RR63: struck through, narrowed, or marked decided with this ticket, to match.

## Out of scope
- The normal path (a new file renamed over the target), which has no such window.

## Acceptance
- [ ] The choice and its reason in internal/dataplane/dns/doc.go, and RR63 updated to match.
- [ ] A test of what a reader can see during an in-place rewrite (a fake writer stopped between its steps), mutation-checked.
- [ ] The in-place lab test (resolvconf_mount_linux_test.go) passes in `make lab-test`.
- [ ] `make lint`, `make test` pass.

## Notes
- Found in TP-217's review (round 1, finding R1.2); in the product since the fallback was added, not caused by TP-217.

## Log
- 2026-11-15 created in backlog (from TP-217 review R1.2)
