---
id: TP-128
title: "dns: an untold resolv.conf test reads a half-written uplink file"
milestone: M2
area: tests
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
`TestResolvConfWhileUntoldAStubTargetWithoutUplinkWarnsNothing` passes under load. Its failure is explained, and the product's behaviour on an empty uplink file is decided.

## Scope
- **The failure.** Seen once in a lab run under load (2026-10-22, TP-126's lab run, LAB_P=1 with another lab busy): "told [], want 198.51.100.53". The test then passed 20 of 20 alone.
- **Likely cause.** The test creates the uplink file with `os.WriteFile`, which isn't atomic: it creates the file, then writes it. The configurator's watch can read in between, see an empty uplink, take that as the first good read, and tell an empty list.
  - Check that this is the mechanism. Make the test write the uplink atomically (write a temporary file, then rename), as resolved itself does. Also check whether any other test in the package writes a watched file the same way.
- **Decide the product's behaviour.** Is an existing but empty uplink file a good read with no upstreams, or a failed read? If an empty file can only be a half-written one, treating it as a failed read while untold would be safer. Say which, and why, in the Log.

## Acceptance
- [ ] the cause is shown (e.g. a test that reproduces it deterministically, or the window shown in the code)
- [ ] the test is fixed, and `go test -count=200 -run TestResolvConfWhileUntold ./internal/dataplane/dns/` passes under `stress` or parallel load in the lab
- [ ] `make lint`, `make test` pass

## Notes
- From TP-126's lab run (2026-10-22). The test came with TP-115.

## Log
- 2026-10-22 created in backlog (flake seen in TP-126's lab run)
