---
id: TP-102
title: "Data-plane adapters: one ledger, one layout, one record file"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-109]
owner: ""
branch: ""
---

## Goal
netcfg, routetable, firewall, and dns adapters share one implementation of each cross-cutting primitive so a Windows or Android adapter is not a fourth copy of the Linux ledger and record patterns.

## Scope
- One link/address ledger behind a small ops interface for Linux and Darwin netcfg (`netcfg_linux.go` ~170–227, ~449–538 vs `netcfg_darwin.go` ~171–231, ~685–771).
- Replace the `abandoner` type assertion on `Configurator.Close` (`netcfg.go` ~417) with one semantic for a failed close.
- `routetable/split.go` (~119): compute the route layout once per apply instead of three times via `Config`, `Ahead`, and `OverlayAhead` (`routetable.go` ~486, ~525).
- `trusteddir.ReadFile` / `trusteddir.WriteFile` for the atomic record-plus-boot-session primitive, today in `netcfg/record_darwin.go`, `firewall/token_darwin.go`, and `dns/resolvconf.go` (~321–381).
- Decompose `firewall/guard_darwin.go` `enable()` (~312–379) and `dns/handle.go` `answer()` (~42–158) into readable units without changing behaviour.
- If TP-103 has already landed, add a `funlen` gate at about 80 lines to `.golangci.yml`.

## Out of scope
- Darwin dropped errors on record read and DNS store read (TP-108).
- Port types moving into `dataplane` core and depguard (TP-083).
- Windows/Android adapters (TP-047).

## Acceptance
- [ ] existing netcfg, routetable, firewall, and dns tests pass; lab tests that exercise adapters unchanged or updated with a one-line why
- [ ] `make lint`, `make test`, `make lab-test` pass
- [ ] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Must land before TP-047 so new OS adapters do not copy the current duplication.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-18 depends on TP-109 instead of TP-083: it needs the core-owned ports, and can then run alongside TP-083 (owner)
