---
id: TP-102
title: "Data-plane adapters: one ledger, one layout, one record file"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-109]
owner: "agent-claude"
branch: "tp-102-dataplane-adapters-one-ledger-layout-record"
---

## Goal
netcfg, routetable, firewall, and dns adapters share one implementation of each cross-cutting primitive so a Windows or Android adapter is not a fourth copy of the Linux ledger and record patterns.

## Scope
- One link/address ledger behind a small ops interface for Linux and Darwin netcfg (`netcfg_linux.go` ~170–227, ~449–538 vs `netcfg_darwin.go` ~171–231, ~685–771).
- Replace the `abandoner` type assertion on `Configurator.Close` (`netcfg.go` ~417) with one semantic for a failed close.
- `routetable/split.go` (~119): compute the route layout once per apply instead of three times via `Config`, `Ahead`, and `OverlayAhead` (`routetable.go` ~486, ~525).
- `trusteddir.ReadFile` / `trusteddir.WriteFile` for the atomic record-plus-boot-session primitive, today in `netcfg/record_darwin.go`, `firewall/token_darwin.go`, and `dns/resolvconf.go` (~321–381).
- Decompose `firewall/guard_darwin.go` `enable()` (~312–379) and `dns/handle.go` `answer()` (~42–158) into readable units without changing behaviour.
- Keep every function this ticket writes or touches at about 80 lines or fewer. The `funlen` gate itself is TP-083's: it lands last (tickets/ORCHESTRATION.md "Consolidation phase"); this ticket adds no gate.

## Out of scope
- Darwin dropped errors on record read and DNS store read (TP-108).
- Windows/Android adapters (TP-047).

## Acceptance
- [x] existing netcfg, routetable, firewall, and dns tests pass; lab tests that exercise adapters unchanged or updated with a one-line why
- [x] `make lint`, `make test`, `make lab-test` pass
- [x] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Must land before TP-047 so new OS adapters do not copy the current duplication.
- Close semantic: a failed `Configurator.Close` frees the owner's place on every OS. That is the one deliberate change, and it is on Linux: it used to keep the flock so that Close could be retried. Nothing retried it, and ClearWith abandoned the configurator anyway. Now what a failed Close leaves carries the owner's protocol (Linux) or stays in its record (macOS) for the owner's next configurator, and a second Close returns nil. `Enforcer.Close` called again after a failure retries only the guard's removal, without the owner lock (macOS already behaved this way). No caller retries it.
- `dns/resolvconf.go`'s writer is not on trusteddir: it replaces a world-readable (0644) system file at a fixed path, rewrites in place on a bind mount (EBUSY/EXDEV) and restores a symlink, and trusteddir's walk would refuse macOS test directories (`/var` is a symlink). Only the trusted-directory records (netcfg's route records, the pf guard's token record) share `trusteddir.ReadFile`/`WriteFile`/`Remove`/`BootSession`.
- Small differences from moving the token record onto trusteddir, none of them in what callers check: the record is read whole and then cut to 4 KiB, instead of read through a 4 KiB limit; an `fstat` failure on the just-opened record is now an error rather than a stale record; error texts differ (`firewall:` added on the create error, dropped from the boot-session one).
- Found by a self-review and fixed here (f25c9f0): the shared ledger keyed a link's record by the kernel's name instead of the config's, so on Linux an interface named by an altname was configured and then restored in the same Apply. Pre-existing, left as it was: Close doesn't restore such an interface, because restoreLink compares the kernel's name with the record's and drops the record. Worth a ticket of its own.
- Functions this ticket didn't touch that are over the ~80-line line, for TP-083's funlen gate: `routetable.splitRoutes` (236), `netcfg.Config.Validate` (96), `routetable.(*Enforcer).watch` (91), `dns.(*dynamicStore).apply` (83).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-18 depends on TP-109 instead of TP-083: it needs the core-owned ports, and can then run alongside TP-083 (owner)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-102-dataplane-adapters-one-ledger-layout-record
- 2026-10-19 ticket corrected (orchestrator): the out-of-scope line on port types and depguard dropped (that was TP-109, done); the funlen bullet now says this ticket adds no gate (TP-083 lands last and adds it) and keeps the functions it writes or touches at about 80 lines or fewer
- 2026-10-20 one link/address ledger for Linux and macOS netcfg (`netcfg/ledger.go` behind `linkOps`; b0136bc); a failed Close frees the owner's place on every OS, abandoner gone (c9e0619); `routetable.LayoutOf` computes the layout once per apply (cf63d84); `trusteddir.ReadFile`/`WriteFile`/`Remove`/`BootSession` for netcfg's route records and the pf token record (e4e76dc); the pf guard's `enable` and the resolver's `answer` decomposed (0e45c30); the ledger keys links by the config's name, as Linux did (f25c9f0)
- 2026-10-20 tests changed, each saying why: `netcfg/clear_test.go` checks the Close instead of abandon; `TestAFailedClearFreesTheNamespace` makes a real Close fail (an MTU of -1 to restore, which the kernel refuses) instead of a stubbed one; `routetable` keeps `Config`, `Ahead` and `OverlayAhead` in export_test.go, so its tests are unchanged. Added: `trusteddir` `TestFilesAreReadAndReplacedInPlace`, and the lab test `TestAnAltnameKeepsItsChanges`, which fails without f25c9f0
- 2026-10-20 every function this ticket wrote or touched is 80 lines or fewer (longest: the Enforcer's `apply` 52, Linux's `reconcileRoutes` 44, macOS's 42, `forward` 39); no funlen gate added (TP-083's)
- 2026-10-20 checks at f25c9f0 (`git merge origin/rewrite`: already up to date): make lint exit 0, make test exit 0, make lab-test exit 0 in 396s (LAB_P=1, another lab running; 35 node packages ok, lab suite ok). Earlier make lab-test at 0e45c30: exit 0 in 143s (LAB_P=4)
- 2026-10-20 in-progress → review — not verified here: macOS on a device (netcfg's ledger and route record through the real routing socket, the pf guard's token record and enable path, the resolver's answers); they ran only through their unit tests with fakes and `make lint`'s darwin vet
