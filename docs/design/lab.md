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

What the lab can't show (macOS's routing socket, mDNSResponder, pf, sudo) is shown on a real Mac by `devicetest` ([lab/devicetest](../../lab/devicetest/doc.go)), a Go tool in this repository run only by the owner. Its predecessor was a private bash kit of about 12k lines that ran the checks, judged them and restored the Mac; its bugs cost whole device runs (a guard that voided every capture, decodes to empty text that made checks unable to fail), and its tests were stubs that couldn't reproduce root, routing or setuid behaviour.

Decisions:

- **Record, don't judge.** A run saves evidence (root reads, a capture, snapshots, `thinkpol diag`, timestamps) and never decides PASS or FAIL; an agent judges the evidence afterwards, and a judgement that recurs becomes a Go test over a recorded fixture or a `diag` field.
- **Go, in this repository**, against Python or keeping bash. Go calls the product's own readers (firewall's pf readers, trusteddir, netcfg's default-route lookup, the lab's pcap reader) where Python or bash would re-parse what the product writes and drift from it, as the kit's copy of the route-record format did. Its safety machinery gets real tests: real processes, kill -9 and fsync on any machine, real root in lab nodes; bash's stubs gave false greens. A static binary runs under sudo with no interpreter to set up. Python would be quicker for one-off steps; a plan is data, so it needs neither.
- **A frozen safety core** ([lab/devicetest/safety](../../lab/devicetest/safety/doc.go)) is the only root code, in a binary of its own that links no plan: typed changes, each with its undo synced to a journal before it is made, a dead-man process, and a restore that compares the Mac with its baseline and keeps a run pending until it is clean. It is pinned by a hash test; changing it takes its own ticket and the owner's approval.
- **Plans are data,** one per ticket, and do only what they list; a ticket's plan is never bigger than its change.
- **A broken recorder is caught before any change:** the capture must see a marker, miss a filtered one and decode through the evidence path within 10 s.
- **Private stays private:** evidence lives outside every git checkout (`~/thinkpol-evidence/`, never pruned), and what names a server will come from a private file, read only by plans that need it.
- **One terminal,** every line timestamped; physical steps are asked for there.
- **Reboot tests print a recovery sheet;** the harness installs nothing that acts at boot.

Migration: the old kit runs the end-of-phase device run as it is, and is retired right after it. Then the harness gains its exit-server driver (a container on the owner's server, everything naming it in the private file), then one plan per M2 ticket as each reaches its device run, then the end-of-phase checklist as a plan. The kit's judging code, stub tests and two-terminal sessions are not ported.
