# thinkpol-vpn — Censor lab design

The censor lab: the test suite and the definition of done for a transport. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Censor lab

The test suite, and the definition of "done" for a transport. Docker Compose with a client, a **censor** container between client and entry, an entry, an exit, an "internet" target and a real site for camouflage. Censor modules, each switchable:

- IP and SNI blocklists
- WireGuard and OpenVPN fingerprints
- fully-encrypted-traffic heuristics (as in *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*, USENIX Security 2023)
- active prober
- JA3/JA4 fingerprint filtering
- whitelist mode: everything whose destination address isn't listed is dropped first, then the name in the handshake is checked; UDP is dropped even to listed addresses; variants throttle the rest (to about 14 kb/s), reset it, or let it time out. A name-only check, still seen on some lines, is a separate, weaker module
- volume-based throttling

Besides censor modules, the lab runs two non-censor checks:
- **Isolation:** two spaces share an entry, and every attempt to reach across fails.
- **Seizure:** a snapshot of a node's disk and memory is searched for member IPs, names and destinations.

`make lab` runs every transport against every module and regenerates a pass/fail matrix committed as `lab/RESULTS.md`. A cell passes only when data crossed over IPv4 and IPv6, and a cell whose censor can't be trusted is an error, never a pass: the matrix is honest or not written.

## Device testing

What the lab can't show (macOS's routing socket, mDNSResponder, pf, sudo) is shown on a real Mac by `devicetest` ([lab/devicetest](../../lab/devicetest/doc.go)), a Go tool in this repository run only by the owner (TP-082). Decisions:

- **Record, don't judge.** A run saves evidence (root reads, captures, snapshots, `thinkpol diag`, timestamps) and never decides PASS or FAIL; an agent judges the evidence afterwards, and a judgement that recurs becomes a Go test over a recorded fixture or a `diag` field (ORCHESTRATION.md "Device testing").
- **A frozen safety core** ([lab/devicetest/safety](../../lab/devicetest/safety/doc.go)) is the only root code: typed changes, each with its undo synced to a journal before it is made, a dead-man process, and a restore that compares the Mac with its baseline. It is pinned by a hash test; changing it takes its own ticket and the owner's approval.
- **Plans are data,** one per ticket, and do only what they list; a ticket's plan is never bigger than its change.
- **A broken recorder is caught before any change:** each capture must see a marker, miss a filtered one and decode through the evidence path within 10 s.
- **Private stays private:** evidence lives outside every git checkout (`~/thinkpol-evidence/`), and what names a server comes from a private config file read only by plans that need it.
- Reboot tests print a recovery sheet; the harness installs nothing that acts at boot.
