---
id: TP-174
title: "Hygiene: ticket ids in comments, missing doc.go, lab logging, shared fakes"
milestone: M2
area: repo
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Small cleanups that keep the code readable on its own: comments state the constraint, not the ticket that found it; every package says what it is; logging is one style; test fakes exist once.

## Scope
- **Ticket ids in production comments:** 112 comment lines in non-test `.go` files (outside `proto/gen/`) cite a `TP-` or `KRN-` id. Each becomes the constraint it stands for; the id stays only where it names work not done yet.
- **doc.go** for `internal/dataplane/checksum`, `checksum/checksumtest`, `packettest`, `transport/memory` and `transport/transporttest`, or an AGENTS.md rule exempting test-only packages (`*test`, `memory`) with the reason.
- **The lab binaries:** `lab/censord` and `lab/labdns` log with the standard `log` package, `lab/labctl` prints to stderr; move them to `log/slog`, or document the exception in lab/README.md.
- **Duplicated test fakes:** `fakeClock` (`internal/dataplane/path/fixture_test.go`, `internal/dataplane/routetable/guard_test.go`) and `fakeConfigurator` (`internal/dataplane/netcfg/clear_test.go`, `internal/dataplane/routetable/routetable_test.go`) shared from one test helper package, where their behaviour is the same.

## Out of scope
- Behaviour changes.
- Ticket ids in tests, docs and the board.

## Acceptance
- [ ] `grep -rnE '//.*\b(TP|KRN)-[0-9]+' --include='*.go'` outside tests and `proto/gen/` lists only comments that name work not done yet
- [ ] every package under `internal/` has a doc.go, or falls under a written exemption
- [ ] the lab binaries log through `slog`, or lab/README.md says why not
- [ ] each fake is defined once (or the Notes say why two differ)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: a code-quality pass on 2026-11-07, recorded at the TP-139 owner session, 2026-11-07.
- Counts and paths checked at filing: 112 comment lines with ticket ids (all outside `lab/`); the five packages have no doc.go; `fakeClock` and `fakeConfigurator` are each defined twice.

## Log
- 2026-11-07 created in backlog
