---
id: TP-103
title: "supervisor: split the file, no test globals in production"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: []
owner: agent-glm
branch: tp-103-supervisor-split-file-no-test-globals
---

## Goal
The Linux supervisor is several focused files with test-only hooks behind options, not package globals in the production build.

## Scope
- Split `internal/agent/supervisor/supervisor_linux.go` along its natural seams (state machine ~48–644, worker record ~646–778, process lifecycle ~780–1199); shorten `run` (~814–1028) and isolate `applyIsolation` (`isolation_linux.go` ~199–353).
- Move test-only package state out of production builds: `failApplyIsolation`, `unboundAccepts` (`isolation_linux.go` ~105, ~110), `writeSysctl`, `procSys` (`forwarding.go` ~18, ~284); sysctls behind an interface on `Options`, fault injection via an unexported hook option.
- Untangle `shared.go` listener lifecycle from the reply-window tracker.
- If TP-102 has already landed, add a `funlen` gate at about 80 lines to `.golangci.yml`; otherwise the sibling ticket owns that gate.

## Out of scope
- Changing isolation semantics or worker sandboxing rules.
- `cgroup_linux.go` rmdir retry behaviour unless a test needs it.

## Acceptance
- [x] supervisor unit and lab tests pass unchanged or each change explained in the test — no assertion changed; the tests' hook plumbing moved to the Options fields (forwarding_test.go fake, rollback_linux_test.go failRebuilds, egress_linux_test.go WithUnboundAccepts), each noted in its diff; isolation_golden_linux_test.go added
- [x] `make lint`, `make test`, `make lab-test` pass — lint clean on every OS, test ok, lab-test ok 35 packages @ f120fca (finished 2026-10-19, round 2)
- [x] no behaviour change: existing tests pass unchanged, or each changed test says why — the golden lab test pins the nftables rules byte-identical across the rule-builder refactor (goldens generated from the pre-refactor code at c171664)

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Review findings
Round 2. All three reviewers said merge; the items below are the design reviewer's, plus a coverage gap.

- [x] R2.1 Test hooks are set at `New` and never written on a live supervisor: `failIsolation` goes through a small `rebuildFailer` with an atomic armed flag (set at `New`, armed/disarmed atomically); the sysctl write hook likewise (atomic.Pointer). Rewrite `rollback_linux_test.go`'s `failRebuilds` and `hookSysctls` users accordingly. — done (11df02d); tests needing the failer now pass it in `Options` at `New` (`probeOptions`, the rollback and forwarding tests)
- [x] R2.2 `tableState` holds everything the tables are built from (`egressAllowed`, the two transit prefixes, `unbound`); `applyIsolation` → `buildIsolation(st)` is a plain function of the state; `addSpaceOut`/`addMasquerade` take the state, not `Options`; `slices.Concat` for `egressBlocked`; the golden test calls `buildIsolation(goldenState())` without a fake `Supervisor`. — done (dab10df); all three goldens reproduced byte for byte
- [x] R2.3 A second golden state: no uplink, IPv6 forwarding owned, no flow cap, zero slots (what `New` installs). Capture it from the code before R2.2's change, so it proves the refactor; say in the Log how it was captured. Add a `-update` flag to write testdata instead of printing. — done (e20e880, recaptured in dab10df, see Log)
- [x] R2.4 `replies.go`: a `replyPeers` type owns the reply tracker (`mu`, `links`, `remotes`, `swept`; `remember` reports eviction; `replyTo`); route holds `*replyPeers`; `shared.go` stops building its maps. — done (c6c55f4); the route holds `replyPeers` by value, and `remember` returns the eviction for the caller to count
- [x] R2.5 `serve` (~95 lines) and `SetSpaces` (~90) under ~80 lines: session methods `sendInitial`/`stop`/`sendListeners`/`sendSeeds`/`sendConfig`/`readReplies`, `sn.stuck`; `validateSpaces(spaces)` for `SetSpaces`' loop; `newSession` constructor creating `ready`/`gone`; move the session to `session_linux.go` if `process_linux.go` is then mostly session. — done (e8ac082): serve 64 lines, SetSpaces 79; the session moved to session_linux.go, process_linux.go keeps the process lifecycle
- [x] R2.6 Nits: `forwarding`'s sysctl interface drops `ReadDir` (`Glob` covers `accept_ra`); one `hookSysctls` fake (`fakeKernelSys` embeds it); the rules struct's chain list in its own block; compute state once before the loops (~337-340); `accept()` instead of `verdict(kind)`; `installIsolation` next to `applyIsolation`, `established` into `egress_linux.go`; `applySpaceTable` uses the same style as the root tables; the `unboundAccepts` explanation once (on `Options`), others point there; cgroup comment says "retries every 2 ms, about 100 ms in all" and no sleep after the last try; return `sn.p.err` directly. — done (spread over 11df02d, dab10df, e8ac082, f120fca); the test-side `accept` helper became `acceptLink` to free the name

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-103-supervisor-split-file-no-test-globals
- 2026-10-19 in-progress → review — file split (supervisor_linux.go keeps the state machine; worker_linux.go, process_linux.go new); run split into startWorker, markStarted and a session (awaitReady, serve); applyIsolation's rule DSL one method per chain; shared.go split (replies.go); test-only globals moved behind Options (sysctls interface, failIsolation, unboundAccepts hooks); cgroup rmdir retries back off 2 ms (on the task prompt's order, though the ticket's out-of-scope lists it); funlen gate skipped: TP-102 is still in backlog, its ticket owns the gate
- 2026-10-19 review → has-errors — round 2 review: all three reviewers said merge; the design reviewer's items and a coverage gap written up as R2.1–R2.6
- 2026-10-19 has-errors → in-progress — agent-glm picks up R2.1–R2.6
- 2026-10-19 R2.3: the fresh-state golden captured from the pre-refactor builders @ 11df02d, by a temporary change to the golden test (a fake supervisor applying the state), first with the test's EgressAllowed inherited, recaptured with it empty the same way before the R2.2 commit; the refactor reproduces all three goldens byte for byte @ dab10df
- 2026-10-19 in-progress → review — R2.1–R2.6 done; make lint, make test, make lab-test pass @ f120fca (lab-test: 35 packages)
- 2026-10-19 review round 2: correctness and design reviewers: merge after small items, applied by the orchestrator: the rollback test disarms the failer instead of writing a live supervisor's options; the hooks' comment matches the code; applySpaceTable has its doc back; tablesInput is egressBeforeRebuild (saveEgress/restoreEgress); the extra control-socket close on EOF, not in the old code, removed; make lint, make test, make lab-test LAB_P=1 green (make's exit 0, 35 in-node packages)
