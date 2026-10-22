---
id: TP-091
title: "Device diagnostics snapshot (`thinkpol diag`)"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-078]
refs: [DESIGN#the-local-api]
owner: "agent-tp-091"
branch: "tp-091-device-diagnostics-snapshot"
---

## Goal
`thinkpol diag` writes one snapshot of everything the agent changed on the host and what the host shows of it. That snapshot is the evidence a real-device run records and an agent judges afterwards. Device checks shrink to "do the step, save `diag` and a capture". The parsing and judging that the device-test kit did in bash now lives in Go: it is tested, and it ships to users for support.

## Scope
- A local API call and a `thinkpol diag` command that print a versioned JSON snapshot (`-o FILE` writes it at mode 0600). The snapshot holds:
  - the status the local API already serves;
  - the routes, rules and addresses the agent owns, as the host reports them;
  - the IPv6 leak guard:
    - on macOS: the pf anchor's rules with their counters, the exempt table, the agent's `pfctl -E` reference and whether pf still holds it, and pf's enabled state;
    - on Linux: the nftables guard table with its counters;
  - DNS: the resolvers the host uses for the overlay's domains and for everything else;
  - the TUN: its name, MTU, addresses and state;
  - the last Apply's steps with their timings.
- Every field the agent cannot read says why (`"unreadable": "<reason>"`), never just empty, so a judge can tell "nothing there" from "couldn't look".
- No secrets: no keys, tokens' secret parts, or session ids. Endpoints and addresses are in, because the user is the one reading them.
- Read-only: `diag` changes nothing on the host. Unprivileged callers get what the socket's permissions allow.

## Out of scope
- Judging the snapshot (PASS/FAIL). That's done after a run, by an agent reading the snapshot and the capture. If a judgement repeats often enough to code, it goes into the lab or a Go test over recorded fixtures, not into a device script.
- Windows (TP-047 adds its parts).

## Acceptance
- [ ] `thinkpol diag` on Linux in the lab: the guard table, routes, rules and resolvers match what `nft`/`ip` report, in a test
- [ ] macOS: the pf parts are parsed from `pfctl` output by functions tested on recorded fixtures, including an unparseable line (→ `unreadable`) and an empty anchor
- [ ] a test checks that no secret field from the config or status reaches the snapshot
- [ ] the snapshot carries a schema version; DESIGN.md's local API section describes it

## Notes
- **Origin (2026-10-16).** The private device-test kit for TP-078 grew to about 10,000 lines of bash against about 3,000 lines of product change (tests included), most of it judgement logic: parsing tcpdump and pfctl output and deciding PASS or UNKNOWN. Its stub tests could never reach real root, routes or tcpdump, so every review round found new ways a check could PASS wrongly. See ORCHESTRATION.md "Device testing (2026-10-16)".
- After this ticket, TP-078's checks 08 and 10 reduce to `thinkpol diag` before, during and after, plus a capture.

## Log
- 2026-10-16 created in backlog (device-test kit rethink)
- 2026-10-22 backlog → in-progress — owner: agent-tp-091, branch: tp-091-device-diagnostics-snapshot
- 2026-10-22 plan, one slice per commit, each shown working before the next: (1) a `Diagnose` local API call and `thinkpol diag [-o FILE]` (0600), schema version 1, with the status, the TUN as the host reports it, and the secret-field test; (2) Linux: the routes and rules the agent's owners hold and the nftables guard with its counters, read from the host, with a lab test against `ip -j` and `nft -j`; (3) macOS: the pf anchor's rules with counters, the exempt table, the `-E` reference and whether pf holds it, pf enabled, parsed by functions tested on recorded fixtures (never real pfctl), and the routes from the RIB; (4) DNS: the resolvers the host uses for the overlay's domain and for the rest; (5) the last Apply's steps with their timings. Host parts (public addresses) are root's: the group's snapshot marks them unreadable
- 2026-10-22 slice 1: `Diagnose` (group and root) and `thinkpol diag [-o FILE]` (written beside the path and renamed, 0600, a symlink replaced, never followed); schema version 1, the agent's OS and version, the status, the TUN as the host reports it (unreadable while the data plane is down). Tests: `TestDiagnoseReadsTheTUNTheDataPlaneRuns`, `TestDiagnosticsHoldNoSecret` (a connected device's keys and link secret in hex, base64 and raw, in every value of the snapshot), `TestTheSnapshotHasNoSecretField` (the schema walked for secret-named fields), `TestDiagnoseServesAVersionedSnapshot`, `TestWriteJSONFileIsTheOwnersOnly`, the member and stranger in `TestCallersAreCheckedByTheirCredentials`; lab `TestDiagShowsWhatTheHostHolds` (the TUN against `ip -j addr`, the file 0600, no key in the output) passes. Mutations, each caught: the TUN read while down; a key in the snapshot; an unreadable part carrying values; the file written in place (mode kept); Diagnose root-only; a `wireguard_key` field in the schema; a wrong MTU (lab)
