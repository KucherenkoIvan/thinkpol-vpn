---
id: TP-275
title: "The lab image pins a Debian package version that was replaced"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-275"
branch: "lab-image-pin-fix"
---

## Goal
The lab image builds again, so `make lab-test` and `make lab-gotest` run. `lab/Dockerfile` pins `nginx=1.22.1-9+deb12u10`; Debian bookworm-security replaced it with `1.22.1-9+deb12u11`, so `apt-get install` exits 100 and every lab run without a cached image fails at the image build.

## Scope
- Check every `pkg=version` pin in `lab/Dockerfile` against what the pinned base image's apt offers now.
- Re-pin each one that is gone to the version Debian ships now, if the upstream version is the same; if the upstream version changed, stop: lab/RESULTS.md was scored against it.
- Say in the Dockerfile comment why a Debian update of the same upstream version keeps the lab's results valid.

## Out of scope
- Re-scoring lab/RESULTS.md (not needed for a Debian revision of the same upstream version).
- Making the build survive future replacements (e.g. snapshot.debian.org): a separate ticket if wanted.

## Acceptance
- [x] Every pin in `lab/Dockerfile` installs from the pinned base image's apt. (apt-cache policy in the pinned base: nginx offers only deb12u11 and deb12u9; openvpn 2.6.14-0+deb12u2 still offered.)
- [x] The lab image builds through the repo's make targets. (`make lab-gotest` at 9978aa72 built the new tag; in it `dpkg-query` shows nginx 1.22.1-9+deb12u11, openvpn 2.6.14-0+deb12u2.)
- [x] A targeted `make lab-gotest PKG=./internal/dataplane/transport/reality/...` passes (the camouflage nginx starts). (9978aa72: ok, 220 PASS, 0 FAIL, 1m23.6s.)
- [x] `make lint` passes. (9978aa72; `make test` green too.)

## Notes
- nginx `1.22.1-9+deb12u10` → `1.22.1-9+deb12u11`: a Debian security revision of the same upstream nginx 1.22.1, so the camouflage site's behaviour the prober and server-hello rows were scored against is unchanged.
- openvpn `2.6.14-0+deb12u2` is still in bookworm and bookworm-security: unchanged.

## Log
- 2026-11-22 filed and backlog → in-progress, owner: agent-tp-275
- 2026-11-22 nginx 1.22.1-9+deb12u10 → 1.22.1-9+deb12u11 (same upstream 1.22.1); openvpn pin unchanged; lab image built by make lab-gotest, reality package ok in a lab node, make lint and make test green, all at 9978aa72; no new tests (a Dockerfile pin), so no mutations; no full lab run (the orchestrator runs it on rewrite after the merge)
