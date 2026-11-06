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

The censor sees streams, not only packets: each direction of a TCP connection is reassembled in order as a Linux receiver reads it, linked to its reverse, and its first bytes kept for active modules to replay. Where copies of the same bytes differ, it keeps the copy Linux keeps; what Linux discards (a bad checksum, data without ACK, on a SYN or an RST, a segment far past any window) never enters the stream; a new connection on an old one's addresses and ports starts over once the server accepts it. The few discards it doesn't make as Linux does are listed in the package doc's Limits: a transport that passes the censor by one of them proves nothing. A passive module can tag a flow as suspect for an active one, and one module can be both. Verdicts compose by one rule: only drop and reset end the module walk, so one module letting a flow through or throttling it never stops another, or the prober, from blocking it, and a flow's verdict only gives way to a more severe one. Reset sends RSTs to both ends of an established connection; throttling polices both directions of a connection to a rate and never holds packets. The camouflage site sits behind the censor on a network of its own (`lab.Upstream`), so an entry's connection to it crosses the censor as a client's does: the prober's upstream tell is visible there. The package doc of `lab/censor` has the mechanism.

Besides censor modules, the lab runs two non-censor checks:
- **Isolation:** two spaces share an entry, and every attempt to reach across fails.
- **Seizure:** a snapshot of a node's disk and memory is searched for member IPs, names and destinations.

`make lab` runs every transport against every module and regenerates a pass/fail matrix committed as `lab/RESULTS.md`. A cell passes only when data crossed over IPv4 and IPv6 and fails only when it crossed over neither: one family alone is partial, which no cell expects, so a censor one family slips past never scores as blocking. A cell whose censor can't be trusted is an error, never a pass: the matrix is honest or not written.
