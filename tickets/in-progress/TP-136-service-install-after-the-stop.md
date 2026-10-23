---
id: TP-136
title: "service install: recover a never-loaded unit, and say what a failed start leaves"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-046]
refs: [docs/design/security.md#kill-switch]
owner: "agent-tp-136"
branch: "tp-136-service-install-after-the-stop"
---

## Goal
A reinstall never gets stuck on a unit systemd hasn't loaded, and when it fails after stopping the service, it says the service is down and still enabled.

## Scope
From TP-046's round-4 second opinion, which arrived after the merge.

1. **A unit systemd never loaded blocks the next install.** If the first install writes the unit and then dies before `Start` (or `daemon-reload` fails), `systemctl stop` fails with "Unit thinkpol.service not loaded" on every later install, and Install treats that as fatal before `Start`. Only a reboot or a hand `daemon-reload` unsticks it.
   - Fix: treat a unit that isn't loaded as already stopped (or reload before the stop).
   - Test: the fake already refuses `stop` when the unit isn't loaded.
2. **A failed `Start` after a successful stop says only "starting the service: …".** The service is stopped and still enabled: on launchd it's booted out until the next boot.
   - Say that in the error, as the host-lock refusal already does.
   - `service/doc.go`'s "a failed reinstall leaves the service running and enabled" is true only before the stop. Fix it.
3. **Suspicion: launchd may return EIO for a bootstrap that loaded the job.** After the retries, check `launchctl print`: if the job is loaded, the bootstrap worked. Add a test with the fake.

## Acceptance
- [x] a unit-not-loaded `stop` doesn't stop an install (test), and the install then starts the service
- [x] a failed start's error names the state, and the doc agrees (test on the error)
- [x] a bootstrap that returned EIO but loaded the job counts as started (test)
- [x] `make lint`, `make test` pass; the lab's `TestServiceUnderSystemd` passes

## Review findings
Round 1 (2026-10-23): correctness (merge), design (fix first), second opinion (fix first). The three fixes work on the paths the tests build; the failed-start text claims a state install doesn't know, and the lab pins a different case from the one item 1 fixes.
- [x] R1.1 The failed-start text can be false: `defined` only means the file exists, so after a unit that was written but never enabled (this ticket's item 1), a failed `daemon-reload`/`enable`, a hand `systemctl disable`, or a launchd `enable` failing over a disable override, it still says "stopped and still enabled"; the host-lock refusal (`install.go` ~175) too. After a failed `systemctl restart`, `Restart=always` with no start limit puts the unit in auto-restart, so "stopped" / "not running" is false within `RestartSec`. Linux messages name launchd, and the state sentence comes after `%w` (after systemctl's whole stderr). Say only what install knows, per manager (e.g. a `System` method), first and before the wrapped error: the old agent was stopped and the definition is on disk; whether the next boot starts it only if read (`systemctl is-enabled`/`is-active`, `launchctl print-disabled`) or not claimed; a systemd unit whose restart failed may be retried by systemd. Tests: a never-enabled unit with a failed `daemon-reload`, a failed restart, the launchd wording.
- [x] R1.2 The lab pins a different case: `lab/service_test.go` ~59 stops a unit with no file at all; the fake answers "not loaded" for a unit whose file is on disk but never reloaded, which systemd ≥247 likely loads on demand (exit 0). Write the unit file, stop it without a daemon-reload, record and accept what systemd 252 answers (0, or 5 with " not loaded"), make the fake answer that, and reword `systemd.go` ~47, `doc.go` ~18 and the Log to the observed behaviour, with a new Log line naming the exit code seen.
- [x] R1.3 service/doc.go ~44: say the EIO-but-loaded rule (after an EIO, a job `launchctl print` shows counts as started, else the bootstrap is retried) and the first-install failure ("installed, not running"; under systemd, enabled if `enable` ran). The acceptance box "the doc agrees" waits on it.
- [x] R1.4 Nits: `notLoaded` (`systemd.go` ~69-74) accepts the " not loaded" text with any exit code: require exit 5, with the text only as the fallback when no exit code is known; `launchd.go` ~66: when `print` fails after an EIO, `errors.Join` the bootstrap's EIO with it; the fake returns `errors.New("exit status 5")`, so the `*exec.ExitError` branches of `notLoaded`, `inputOutputError` and `noSuchService` never run: test one with a real `*exec.ExitError` (`exec.Command("sh", "-c", "exit 5").Run()`), or say in the Log that only the text path is tested; add a `## Notes` line naming TP-046's round-4 second opinion as the source.

## Log
- 2026-10-23 created in backlog (TP-046 round-4 second opinion, after the merge)
- 2026-10-23 backlog → in-progress — owner: agent-tp-136, branch: tp-136-service-install-after-the-stop
- 2026-10-23 item 1: systemd's Stop and Remove read "Unit … not loaded" (exit 5) as stopped, so a unit an install wrote but never started doesn't block the next install (which then starts it) or uninstall; a stop that fails otherwise still stops the install. Test TestANeverLoadedUnitCountsAsStopped (the fake answers a stop or disable --now of an unloaded unit as systemd does); mutations seen failing: Stop without the tolerance, Remove without it, every stop error read as stopped. Lab TestServiceUnderSystemd pins the fake to systemd: a stop of a unit it doesn't have exits 5 with "not loaded" (mutation: exit 4 expected, seen failing)
- 2026-10-23 item 2: a failed Start says what it left: after the stop, "installed, stopped and still enabled; under launchd, booted out until the next boot"; on a first install, "installed, not running"; service/doc.go says the same (it no longer claims every failed reinstall leaves the service running). Test TestAFailedStartSaysWhatItLeft; mutation seen failing: the reinstall's message dropped
- 2026-10-23 item 3: after a bootstrap refused with EIO, a job `launchctl print` shows counts as started; else it is retried as before. Test TestLaunchdTakesAnEIOBootstrapThatLoadedTheJob; mutation seen failing: no print after the EIO (the retry is refused, the job already loaded)
- 2026-10-23 done: `make lint` and `make test` green; TestServiceUnderSystemd green; full `make lab-test` green on b58f91a (LAB_P=1, other labs running). Not verified on a Mac: launchd's EIO-but-loaded case is the reviewer's suspicion, tested only with the fake
- 2026-10-23 in-progress → review
- 2026-10-23 review → has-errors (round 1: R1.1–R1.4)
- 2026-10-23 has-errors → in-progress — owner: agent-tp-136, round 1 fixes (R1.1-R1.4)
- 2026-10-23 R1.2: the lab recorded systemd 252's answer to a stop of a unit file on disk that was never daemon-reloaded: exit 0 (it loads the file for the stop); the lab test now writes such a file, stops it, accepts 0 or 5 with "not loaded", and installs over it; it still pins a stop of a unit with no file at all (exit 5, "not loaded"). The fake loads an unread unit file for a stop or `disable --now` as systemd 252 does; an oldSystemd mode answers "not loaded" instead. Item 1's Log line amended by this one: the "not loaded" case is a systemd that doesn't load on demand, or no file at all; systemd.go and doc.go say so. Tests: TestANeverLoadedUnitCountsAsStopped (both systemds); mutation seen failing: the "not loaded" tolerance dropped (the old-systemd case)
- 2026-10-23 R1.1: a refused or failed start says first what install knows, then the manager's error: "the installed service was stopped" only when it stopped one, "the definition is on disk", and what the manager reports now (System.State: systemd's is-enabled and is-active, "activating" read as Restart=always retrying; launchd's print and print-disabled), never a state it didn't read; no launchd words under systemd. Tests: TestAFailedStartSaysWhatItLeft (a first install's failed restart, a reinstall's, a never-enabled unit with a failed daemon-reload reading "disabled", launchd's wording); mutations seen failing: the state after the wrapped error, systemd's is-enabled not read, "stopped" claimed on a first install
- 2026-10-23 R1.3: service/doc.go says the EIO-but-loaded rule (after an EIO, a job print shows counts as started, else the bootstrap is retried, a failing print reported with the EIO) and what a first install's failed start leaves (the definition on disk; under systemd, enabled if enable ran)
- 2026-10-23 R1.4: notLoaded decides by exit status 5 when there is one, the text only without; after an EIO, a failing print is errors.Join'ed with it; the fake now returns real *exec.ExitError values (sh -c 'exit N'), so the exit-status branches of notLoaded, inputOutputError and noSuchService run. Tests: TestTheExitStatusDecides, TestAnEIOThenAFailedPrintSaysBoth; mutations seen failing: the text read as not loaded under exit 4, the print's error returned without the EIO. Notes name the source (TP-046's round-4 second opinion)
