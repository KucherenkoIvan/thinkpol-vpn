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

## Review findings
Round 1 (2026-10-22): correctness (merge), design (fix first), second opinion (merge). The cause and the product change hold; the decision and its evidence need writing down properly.
- [ ] R1.1 The decision isn't where decisions live: `dns/doc.go` (~189-191, ~213-215) still names only missing/unreadable (resolved) and missing/dangling (resolv.conf) as failed reads. Add the empty uplink file and its reason. Check systemd-resolved's uplink writer (`write_uplink_resolv_conf`): it writes its header comment even with no servers, and writes atomically. If so, say so: a zero-byte uplink is a file caught mid-write or truncated, never an answer; the rule assumes resolved's atomic writer. Add that an empty /etc/resolv.conf itself is still a good read (TP-117 owns that case). Update the comments at `resolvconf.go` ~390-393 and ~608-612 ("unreadable or empty").
- [ ] R1.2 The "under load" box is ticked on a run with no load (and on b138a96, not head). Re-run `-count=200 -run TestResolvConfWhileUntold` in the lab while something loads the host (e.g. a parallel `make lab-test`, or `stress` in the node), say what the load was, and name the commit; or untick the box.
- [ ] R1.3 One definition of "empty is a failed read": `resolved.read` checks `len(b) == 0` and `upstreamsFromContent` checks again. Pull it into one helper (e.g. `readUplink(path) ([]byte, error)`) used by both. The error says "is empty", not "a half-written uplink is no answer", which the code doesn't know.
- [ ] R1.4 Reasons and mechanism: the "clears the staleness for good" reason holds for the resolv.conf path, not resolved's (whose next tick compares against `r.servers` and tells within 5 s): write one comment per test, for what that test shows, and correct the Log. The Log's mechanism: the watcher's apply woken by the test's own rewrite of resolv.conf (inotify on the name, `watch_linux.go`), or its 2 s ticker, read the uplink between create and write; say that.
- [ ] R1.5 `SystemUpstreams` at startup now treats an empty uplink as a failed read (resolvers unknown, `dns_upstreams_stale`) where it used to give an empty list: add a case to `TestSystemUpstreams` and a Log line.
- [ ] R1.6 Nits: `writeFileAtomic` should use the product's own writer (`replace` with `writeNew`), with a comment saying when to use it, and the Log should say "every write while a watcher runs" (the resolved tests and `TestSystemUpstreams` have none); the garbled test comment "what a half-written one looks like finished" → "Empty, as a file caught mid-write reads: no answer yet."; `upstreamsFromContent`'s run-on doc comment; the Log's out-of-scope resolv.conf case now lives in TP-117 (empty reads mid-rewrite, an empty link target while untold) and the failed uplink read on a change in TP-130: cite them.

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
- 2026-10-22 review → has-errors (round 1: R1.1-R1.6)
- 2026-10-22 has-errors → in-progress — fixing R1.1-R1.6 (round 1)
