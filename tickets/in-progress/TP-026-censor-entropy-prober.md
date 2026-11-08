---
id: TP-026
title: "Censor modules: fully-encrypted heuristics and active prober"
milestone: M2
area: lab/censor
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-064, TP-089]
refs: [C4]
owner: agent-tp-026
branch: tp-026-censor-entropy-prober
---

## Goal
The lab catches traffic that looks like random bytes and servers that don't behave like ordinary web servers.

## Scope
- The exemption rules from Wu et al., "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic" (USENIX Security 2023), on the first data packet of a flow: average set bits per byte, printable prefix, printable fraction, printable runs, TLS/HTTP fingerprints. Apply them to UDP flows too.
- Active prober: on suspected flows, connect to the server with replayed and random payloads; flag servers that answer unlike a normal web server (timeouts, resets, closing after N bytes).
- **JA3S/JA4S** for the server hello (extension order and ALPN included), compared with the camouflage site's fingerprint; the lab matrix uses these results honestly.
- The prober also flags the **upstream tell**, an entry that opens a connection to the camouflage target on every probe (independent design review, 2026-10-13).

## Acceptance
- [ ] a Shadowsocks-like random stream is flagged; HTTPS is not
- [ ] the prober tells a naive echo server from nginx
- [ ] the prober reports the server hello's JA3S/JA4S, extension order and ALPN against the camouflage site's, and detects an entry that opens an upstream connection to the camouflage target on every probe; the results are shown honestly in the matrix

## Notes
- The JA3S/JA4S server-hello comparison is on the MVP path only if D6 requires it (open, 2026-11-07).
- Resolved (owner, 2026-11-07): the server-hello comparison is one of the M2 gate's handshake-level checks, so it stays on the MVP path.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): prober covers the server-side fingerprint and the upstream-connection tell
- 2026-10-15 docs (backlog grooming): owns server JA3S/JA4S computation (TP-032 keeps client fingerprints and whitelist)
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-11-07 notes (owner's MVP cut): the JA3S/JA4S comparison's place on the MVP path is open
- 2026-11-07 notes: the server-hello comparison stays on the MVP path (owner, 2026-11-07)
- 2026-11-09 backlog → in-progress, owner: agent-tp-026
- 2026-11-09 impl: lab/censor gains fully-encrypted (Wu et al.'s five exemptions on a connection's client's first data, TCP stream start and UDP first datagram; drop pinned, or tagOnly for the prober), prober (passive+active: replayed, random 3/16/49/221/1000-byte and own-TLS-handshake probes compared with a reference site; the upstream tell; a found-out server blocked by address and port; UDP suspects flagged Accept "not probed") and server-hello (JA3S, JA4S, version, cipher, extension order, ALPN of a connection's ServerHello against the site's answer to the same ClientHello, the site by name from a sites setting); Flow.Initiator; helloMessage reads ServerHellos too
- 2026-11-09 matrix: cases fully-encrypted, active prober and server-hello (the last two in lab.Upstream with nginx as the camouflage site; cells with an active module probe twice and score the probe after its verdicts, censorCase.settle; their cells quote the module's verdict); reference row random-tcp (socat echo fed random bytes); the https control row now serves nginx (same server and settings as the camouflage site); lab/Dockerfile pins nginx 1.22.1-9+deb12u10 and adds socat
- 2026-11-09 vantage: the brief said the lab censor isn't on the entry's uplink, but lab.Upstream (TP-089) puts the camouflage target behind the router and TestCensorSeesUpstream shows the entry's connection to it crosses the censor; the upstream tell is implemented on what the censor sees there (a connection from the probed address to the site during every probe), doc.go says when a real censor has that vantage; timing is reported in the verdict, not judged (lab round trips are sub-millisecond)
- 2026-11-09 tests: unit (lab/censor) TestLooksFullyEncryptedExemptions, TestFullyEncryptedFlagsRandomNotHTTPS, TestFullyEncryptedJudgesTheClientOnly, TestFullyEncryptedTagOnly, TestServerHelloFingerprints (FoxIO's JA4S example t130200_1301_234ea6891581), TestServerHelloReading, TestServerHelloDifferences, TestServerHelloComparesWithTheSite, TestProberTellsEchoFromWebServer, TestProberComparesTLS, TestProberUpstreamTell, TestProberTagsListedDestinations, TestProberOnTheEngine, TestProberSettings; lab TestFullyEncryptedRandomNotHTTPS, TestProberTellsEchoFromNginx, TestServerHelloAgainstTheSite
- 2026-11-09 mutations, each killed by the tests named: set bits <=3.4→<3.4 and >=4.6→>4.6, printable-prefix rule off, half printable >→>=, printable run >20→>=20, TLS/HTTP rule off, TLS minor <=9→<=10 (TestLooksFullyEncryptedExemptions); never blocks (TestFullyEncryptedFlagsRandomNotHTTPS); servers judged, UDP initiator always true, TCP client bit set on SYN-ACK (TestFullyEncryptedJudgesTheClientOnly); reactions always alike (TestProberTellsEchoFromWebServer, TestProberOnTheEngine); upstream tell off, upstream source ignored (TestProberUpstreamTell); TLS differences ignored, negotiated ALPN ignored (TestProberComparesTLS); blocked servers never blocked (TestProberTellsEchoFromWebServer, TestServerHelloComparesWithTheSite); prober tags nothing (TestProberTagsListedDestinations); hello differences never, extension order ignored (TestServerHelloDifferences); JA4S extensions sorted, JA3S keeps GREASE (TestServerHelloFingerprints); server-hello never flags a mismatch (TestServerHelloComparesWithTheSite)
- 2026-11-09 lab runs (make lab-gotest PKG=./lab): the three lab tests pass; TestCensorMatrix's new cells (every row × off, fully-encrypted, active prober, server-hello) all as expected: udp, wireguard and random-tcp fail fully-encrypted, openvpn udp/tcp and https pass it; random-tcp and openvpn-tcp fail the prober, https passes it (nginx answers every probe and handshake as the camouflage site's does); every row passes server-hello (https matches the site)
- 2026-11-09 make lint, make test green
- 2026-11-09 out of scope: TP-087's branch edits this ticket's backlog copy (a Notes line on TP-201's target), so merging it after this one conflicts on the ticket's path; nginx 1.22 leaves TLS 1.3 out unless ssl_protocols says so, which TP-201's camouflage target needs (startNginx sets it); the prober attributes an upstream connection by the probed source address only, so an entry whose uplink leaves by the other family isn't matched (doc.go)
