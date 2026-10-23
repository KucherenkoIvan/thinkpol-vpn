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

## Log
- 2026-10-23 created in backlog (TP-046 round-4 second opinion, after the merge)
- 2026-10-23 backlog → in-progress — owner: agent-tp-136, branch: tp-136-service-install-after-the-stop
- 2026-10-23 item 1: systemd's Stop and Remove read "Unit … not loaded" (exit 5) as stopped, so a unit an install wrote but never started doesn't block the next install (which then starts it) or uninstall; a stop that fails otherwise still stops the install. Test TestANeverLoadedUnitCountsAsStopped (the fake answers a stop or disable --now of an unloaded unit as systemd does); mutations seen failing: Stop without the tolerance, Remove without it, every stop error read as stopped. Lab TestServiceUnderSystemd pins the fake to systemd: a stop of a unit it doesn't have exits 5 with "not loaded" (mutation: exit 4 expected, seen failing)
- 2026-10-23 item 2: a failed Start says what it left: after the stop, "installed, stopped and still enabled; under launchd, booted out until the next boot"; on a first install, "installed, not running"; service/doc.go says the same (it no longer claims every failed reinstall leaves the service running). Test TestAFailedStartSaysWhatItLeft; mutation seen failing: the reinstall's message dropped
- 2026-10-23 item 3: after a bootstrap refused with EIO, a job `launchctl print` shows counts as started; else it is retried as before. Test TestLaunchdTakesAnEIOBootstrapThatLoadedTheJob; mutation seen failing: no print after the EIO (the retry is refused, the job already loaded)
- 2026-10-23 done: `make lint` and `make test` green; TestServiceUnderSystemd green; full `make lab-test` green on b58f91a (LAB_P=1, other labs running). Not verified on a Mac: launchd's EIO-but-loaded case is the reviewer's suspicion, tested only with the fake
- 2026-10-23 in-progress → review
