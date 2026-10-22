---
id: TP-128
title: "dns: an untold resolv.conf test reads a half-written uplink file"
milestone: M2
area: tests
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-128"
branch: "tp-128-dns-untold-test"
---

## Goal
`TestResolvConfWhileUntoldAStubTargetWithoutUplinkWarnsNothing` passes under load. Its failure is explained, and the product's behaviour on an empty uplink file is decided.

## Scope
- **The failure.** Seen once in a lab run under load (2026-10-22, TP-126's lab run, LAB_P=1 with another lab busy): "told [], want 198.51.100.53". The test then passed 20 of 20 alone.
- **Likely cause.** The test creates the uplink file with `os.WriteFile`, which isn't atomic: it creates the file, then writes it. The configurator's watch can read in between, see an empty uplink, take that as the first good read, and tell an empty list.
  - Check that this is the mechanism. Make the test write the uplink atomically (write a temporary file, then rename), as resolved itself does. Also check whether any other test in the package writes a watched file the same way.
- **Decide the product's behaviour.** Is an existing but empty uplink file a good read with no upstreams, or a failed read? If an empty file can only be a half-written one, treating it as a failed read while untold would be safer. Say which, and why, in the Log.

## Acceptance
- [x] the cause is shown (e.g. a test that reproduces it deterministically, or the window shown in the code)
- [x] the test is fixed, and `go test -count=200 -run TestResolvConfWhileUntold ./internal/dataplane/dns/` passes under `stress` or parallel load in the lab
- [x] `make lint`, `make test` pass

## Notes
- From TP-126's lab run (2026-10-22). The test came with TP-115.

## Log
- 2026-10-22 created in backlog (flake seen in TP-126's lab run)
- 2026-10-22 backlog → in-progress — owner: agent-tp-128, branch: tp-128-dns-untold-test
- 2026-10-22 the cause: the test wrote the watched files with os.WriteFile, which creates the file empty and writes it; the watch's ticker reading in between took the empty read as the first good read with no upstreams, cleared untold and told nil, so the later real first good read was swallowed ("told []")
- 2026-10-22 the tests now write watched files through a temporary file and a rename (writeFileAtomic), as the product's own writers do; every test write to a watched file in the package converted
- 2026-10-22 decided: an existing but empty uplink file is a failed read, not a good read with no upstreams — a zero-byte read cannot be told from a half-written file, and a false "no upstreams" while untold clears the staleness for good, while a failed read only waits for the next tick; a file with content that names no servers is still a good read
- 2026-10-22 added TestResolvConfAnEmptyUplinkFileIsAFailedRead and TestResolvedAnEmptyUplinkFileIsAFailedRead; both fail ("told []") before the change and pass after, checked on darwin and in the lab
- 2026-10-22 verified: go test -race -count=200 -run TestResolvConfWhileUntold on darwin passes; make lab-gotest with -count=200 passes 200/200 (commit b138a96); make lint, make test, make lab-test pass
- 2026-10-22 not verified: a half-written uplink file caught in the product itself — resolved writes its own uplink file atomically, so the empty-read decision rests on the reasoning and the new tests, not on an observed occurrence
- 2026-10-22 out of scope, for another ticket: an empty resolv.conf read while unmanaged (a DHCP client rewriting it in place) is still a good read with no upstreams on the resolv.conf path itself; the same reasoning would make it a failed read too
- 2026-10-22 in-progress → review
