---
id: TP-175
title: "Dependencies: vulncheck is clean again (brotli, compress via utls)"
milestone: M2
area: repo
stream: verification
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
- [x] `make lint` passes, vulncheck included
- [x] `make test` passes
- [x] the lab reality prototype's tests pass: `make lab-gotest PKG=./lab/prototypes/reality`
- [x] go.mod and go.sum change only for the upgraded modules and what they pull in

## Notes
- Found 2026-11-07 when merging TP-139: the advisories are new; rewrite's code did not change.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-175
- 2026-11-07 govulncheck: brotli v1.0.6 → v1.2.7 (GO-2026-6888), klauspost/compress v1.18.7 → v1.20.2 (GO-2026-6865); `go get` of both, `go mod tidy` (adds xyproto/randomstring v1.0.5, required by brotli v1.2.7). No code changed; no new tests, so no mutation check. Commit dd8aaab.
- 2026-11-07 ran on dd8aaab: `make lint` exit 0 (vulncheck: 0 vulnerabilities for darwin, linux, windows, android); `make test` exit 0; `make lab-gotest PKG=./lab/prototypes/reality` passes, but TestRealityClientInterop SKIPs because labctl compiles without `-tags lab`; `go test -tags lab -count=1 ./lab/prototypes/reality` under the shared docker lock: TestRealityPrototype PASS (10.8 s), so the reality prototype was checked with the lab tag.
- 2026-11-07 not verified: full `make lab-test` (not required for this ticket by the owner).
- 2026-11-07 out of scope, found: `labctl gotest` builds test binaries without `-tags lab`, so `make lab-gotest` never runs lab-tagged tests (TestRealityPrototype, TestRealityClientInterop's real config). Follow-up needed.
- 2026-11-07 in-progress → review
- 2026-11-07 review → done, merged into rewrite (go.mod/go.sum only; diff read by the orchestrator)
