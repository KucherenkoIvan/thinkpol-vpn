---
id: TP-175
title: "Dependencies: vulncheck is clean again (brotli, compress via utls)"
milestone: M2
area: repo
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-175"
branch: "tp-175-vulncheck-brotli-compress"
---

## Goal
`make lint` passes again on `rewrite`. Today `govulncheck` reports two advisories in modules that reach the build through `github.com/refraction-networking/utls`, used by `lab/prototypes/reality`: GO-2026-6888 (`github.com/andybalholm/brotli`) and GO-2026-6865 (`github.com/klauspost/compress`).

## Scope
- Upgrade `github.com/andybalholm/brotli` and `github.com/klauspost/compress` to the fixed versions. Upgrade directly, or upgrade `github.com/refraction-networking/utls` if a release pulls in the fixed versions.
- `go mod tidy`.
- Nothing else changes.

## Out of scope
- Other dependency upgrades.
- Code changes beyond what a version bump forces.

## Acceptance
- [ ] `make lint` passes, vulncheck included
- [ ] `make test` passes
- [ ] the lab reality prototype's tests pass: `make lab-gotest PKG=./lab/prototypes/reality`
- [ ] go.mod and go.sum change only for the upgraded modules and what they pull in

## Notes
- Found 2026-11-07 when merging TP-139: the advisories are new; rewrite's code did not change.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-175
