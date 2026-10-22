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
- [ ] a unit-not-loaded `stop` doesn't stop an install (test), and the install then starts the service
- [ ] a failed start's error names the state, and the doc agrees (test on the error)
- [ ] a bootstrap that returned EIO but loaded the job counts as started (test)
- [ ] `make lint`, `make test` pass; the lab's `TestServiceUnderSystemd` passes

## Log
- 2026-10-23 created in backlog (TP-046 round-4 second opinion, after the merge)
- 2026-10-23 backlog → in-progress — owner: agent-tp-136, branch: tp-136-service-install-after-the-stop
