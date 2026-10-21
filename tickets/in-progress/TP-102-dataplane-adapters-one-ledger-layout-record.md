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
- Close semantic: a failed `Configurator.Close` frees the owner's place on every OS. That is the one deliberate change, and it is on Linux: it used to keep the flock so that Close could be retried. Nothing retried it, and ClearWith abandoned the configurator anyway. Now what a failed Close leaves carries the owner's protocol (Linux) or stays in its record (macOS) for the owner's next configurator, and a second Close returns nil. `Enforcer.Close` called again returns nil and touches nothing, the guard included: the guard is removed only under the route table's owner lock, which the first Close let go of (it used to retry the guard's removal, on macOS without the lock). No caller calls it twice.
- `dns/resolvconf.go`'s writer is not on trusteddir. Its original must outlive the boot (DESIGN.md: the OS gets its configuration back "even after a crash or a reboot"), where a trusteddir record is boot-scoped and means nothing after a reboot; and it replaces a world-readable (0644) system file at a fixed path in `/etc`, rewrites it in place on a bind mount (EBUSY/EXDEV) and restores a symlink, none of which a trusted-directory record does. Only the trusted-directory records (netcfg's route records, the pf guard's token record) share `trusteddir.ReadRecord`/`WriteRecord` (the boot-session stamp and its check, `ErrOtherBoot`, `ErrNoBoot`) over `ReadFile`/`WriteFile`/`Remove`, and `BootSession`; each keeps its own policy (netcfg: another boot is empty, no boot line is corrupt; the pf guard: both are stale).
- Small differences from moving the records onto trusteddir, none of them in what callers check: the token record is read whole, without its old 4 KiB cut; an `fstat` failure on the just-opened record is now an error rather than a stale record; error texts differ (`firewall:` added on the create error, dropped from the boot-session one). The boot line is read one way for both: blank and comment lines before it skipped after trimming spaces, then the first word `boot` and the rest the session; so netcfg now also takes a boot line with surrounding or inner whitespace (it took `boot <session>` exactly), and a session with spaces is another boot for both, as before.
- Found by a self-review and fixed here (f25c9f0): the shared ledger keyed a link's record by the kernel's name instead of the config's, so on Linux an interface named by an altname was configured and then restored in the same Apply. Pre-existing, left as it was: Close doesn't restore such an interface, because restoreLink compares the kernel's name with the record's and drops the record. Filed as TP-119.
- Functions this ticket didn't touch that are over the ~80-line line, for TP-083's funlen gate: `routetable.splitRoutes` (236), `netcfg.Config.Validate` (96), `routetable.(*Enforcer).watch` (91), `dns.(*dynamicStore).apply` (83).
- macOS device checklist items that cover this ticket, for the phase-end run. TP-019's (Notes of tickets/done/TP-019-macos-dataplane.md): steps 1–3 (the utun's interface and addresses through the ledger, the routes and their record), 7–9 (re-applies after sleep, a Wi-Fi change and a hostile route: the layout computed once per apply), 10–12 (disconnect and connect, down leaves nothing, crash recovery: a crashed run's record taken over and cleared), 6 and the next-run check 8 (the resolver's answers, `resolver.arpa` NXDOMAIN). TP-078's (Notes of tickets/done/TP-078-macos-ipv6-leak-guard.md): 0 (no token record before), 1–2 (enable and the token record), 7 (pf disabled from outside: a new reference, the old one released), 9–11 (a crash keeps the record, a `-connect=false` start clears it, takeover and clean stop).

## Review findings
Round 1 (2026-10-21): correctness (merge), second opinion (merge), design (fix first).
- [x] R1.1 The boot-session record is still two implementations: `netcfg/record_darwin.go` and `firewall/token_darwin.go` each write "boot <session>" after a header and parse it back their own way. Move stamping and checking into trusteddir (e.g. `WriteRecord(dir, name, header, body)` / `ReadRecord(dir, name) (body, error)` with `ErrOtherBoot`, `ErrNoBoot`), each caller keeping its own policy (netcfg: other boot → empty, no boot line → corrupt; firewall: both → stale). Drop the `bootSession()` pass-through.
- [x] R1.2 `Enforcer.Close` (`routetable.go` ~588) says a second Close retries the guard's removal. Now that a failed Close frees the owner lock, that retry would run without it and could delete another owner's live nft guard. A second Close returns nil without touching the guard; drop the retry sentence (comment, ticket Notes), and make DESIGN.md (~135, "only while it holds the route table's owner lock") true.
- [x] R1.3 `trusteddir.WriteFile`'s doc: callers serialise writes to one name; `name.tmp` is reserved; atomic for readers and process crashes, not durable across power loss (no directory sync), which boot-scoped records don't need.
- [x] R1.4 DESIGN.md (~280) still describes trusteddir as opening directories and locking in them: add reading and replacing records and the boot session.
- [x] R1.5 `guard_darwin.go`: `Close` keeps its own inline copy of the pid-only token resolution that `resolveToken` now does; one helper for both.
- [x] R1.6 The embedded `ledger` makes its methods read as the configurator's (`c.release(...)`, `c.addrs` next to `ops.addrs`): a named field (`links ledger`, `c.links.release(...)`).
- [x] R1.7 Untested: the token record's stale handling (a symlink, a fifo, garbage `pf-guard.token` → stale and removed); the Linux failed-Close paths beyond the restore failure (Close failing on its first dump; a successor taking over the routes left behind; a second Close returning nil). Add them.
- [x] R1.8 `ledger.go` hard-codes `unix.EEXIST`: a per-OS `exists(err)` next to `gone`, so a third OS doesn't edit the shared ledger.
- [x] R1.9 Nits: `linkOps` says addresses are keyed by index because that's all the ledger keeps; `netlinkOps()` vs `*netlinkLinks`: one name; the ledger's vague doc comments ("wanted is what a config keeps of the ledger", "configure configures every interface") say what they hold/do; `maxTokenRecord` cut after a whole-file read protects nothing (a size limit in `ReadFile`, or drop it); `trusteddir.Lock` returns `ErrNotRegular` wrapped instead of an ad-hoc string; `dns/handle.go` `route()` → `routeOrAnswer`, `upstreamsFor()` (it counts) → `pickUpstreams` or move the counting into `answer`; `TestFilesAreReadAndReplacedInPlace` (it replaces by rename) → `…InTheDirectory`; `routetable/doc.go` still says "Config is the layout as netcfg configuration".
- [x] R1.10 Comments state constraints, not history: `clear_test.go` ~8-10, `netcfg_linux_test.go` ~959, ~1159 ("TP-102: …", "(TP-102 Notes)"). The altname Close gap is filed as TP-119: point the test comment there, and make `TestAnAltnameKeepsItsChanges`'s Close part say what it does check.
- [x] R1.11 Ticket: the resolvconf.go exclusion's strongest reason is DESIGN's "even after a crash or a reboot" (the original must outlive the boot; a boot-session record is the opposite) plus the world-readable /etc file, in-place rewrite on bind mounts and symlink restore; drop the macOS `/var` test-directory argument. Name the macOS device checklist items that cover these changes for the phase-end run.

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
- 2026-10-21 review → has-errors (round 1: R1.1–R1.11)
- 2026-10-21 has-errors → in-progress (round 1 findings)
- 2026-10-21 merged origin/rewrite first (5476bcd, no conflicts), not just before the lab run: `make lint`'s vulncheck failed on go1.26.9 (GO-2026-6809 in crypto/x509), and rewrite's go1.26.10 (TP-116) fixes it
- 2026-10-21 round 1: R1.2 a second `Enforcer.Close` returns nil without touching the guard, DESIGN.md and Notes say so (6687ac6); R1.1 `trusteddir.WriteRecord`/`ReadRecord` (`ErrOtherBoot`, `ErrNoBoot`) stamp and check the boot session for both records, netcfg's `bootSession()` gone, boot stays a parameter so tests can stamp another boot; R1.3 `WriteFile`'s doc; R1.9 the 4 KiB cut dropped, `Lock` wraps `ErrNotRegular`, `TestFilesAreReadAndReplacedInTheDirectory` (41df559); R1.5 `resolvedToken`, one helper for `resolveToken` and `Close` (69d0c81); R1.6 `links ledger` with maps `changed` and `ownedAddrs`, R1.8 per-OS `exists`, R1.9 `netlinkOps` and the ledger's comments (ff8dbb0); R1.7 Linux failed-Close test, R1.10 test comments, TP-119 named (45aa298); R1.9 `routeOrAnswer`, `pickUpstreams`, routetable/doc.go, R1.4 DESIGN.md's trusteddir line (8ee58fa); R1.11 Notes
- 2026-10-21 tests added, each failing under a mutation and passing restored: `routetable` `TestASecondCloseLeavesTheGuardAlone` (Close's early return for a closed Enforcer removed: the second Close failed and closed the guard twice); `trusteddir` `TestRecordsAreReadOnlyInTheirBoot` (the boot comparison removed: another boot read back; `f[0] != "boot"` made a prefix match: a glued `bootX` taken as another boot instead of ErrNoBoot) and `TestLock`'s fifo now asserts `ErrNotRegular` (the ad-hoc string put back: fails); `firewall` `TestAStaleTokenRecordIsRemovedAndReleasesNothing` (O_NOFOLLOW dropped from `ReadFile`: the symlinked record released their reference; the ErrNotRegular stale case removed: the fifo failed Close and Apply; the ErrNoBoot stale case removed: garbage failed both); `netcfg` lab test `TestAFailedCloseLeavesItsRoutesToTheOwnersNext`, whose Close fails on its first dump (`/dev/null` put over the configurator's netlink socket) (Close returning before freeing the lock on error: the second Close failed and the next configurator got ErrBusy; a second Close returning ErrClosed: fails; removeOwned skipping routes: the next configurator's Close left them), run with `make lab-gotest`
- 2026-10-21 R1.5 and R1.6/R1.8 are refactors with no new test: existing tests cover them (`resolvedToken` returning t unresolved fails `TestAnUnreadableTokenIsNotTakenTwice`)
