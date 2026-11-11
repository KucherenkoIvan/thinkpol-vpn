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
- [x] a Shadowsocks-like random stream is flagged; HTTPS is not
- [x] the prober tells a naive echo server from nginx
- [x] the prober reports the server hello's JA3S/JA4S, extension order and ALPN against the camouflage site's, and detects an entry that opens an upstream connection to the camouflage target on every probe; the results are shown honestly in the matrix

## Notes
- The JA3S/JA4S server-hello comparison is on the MVP path only if D6 requires it (open, 2026-11-07).
- Resolved (owner, 2026-11-07): the server-hello comparison is one of the M2 gate's handshake-level checks, so it stays on the MVP path.
- The lab camouflage target the prober and the server-hello comparison point at is built in TP-201 (split from TP-087, 2026-11-08): a lab container reality's listener splices to.
- Resolved (owner, 2026-11-09): the upstream tell is reported, not gated. The prober's `upstreamTell` setting is "flag" (default) or "report"; TP-201's reality rows use "report" (milestones.md, lab.md, RR31 say so).

## Review findings
- [x] R1.1 (blocker) the prober tags a flow on its first data segment, so a ClientHello spanning two segments (a post-quantum key share, ~1.8 KB) skips the TLS comparison with a false reason and the replay probe sends half a hello: wait for the whole hello (or not a hello, or retainBytes) before tagging; an incomplete hello gets its own reason
- [x] R1.2 server-hello's "not compared" (site unreachable, name not in sites, no ServerHello) scores pass: a cell whose case expects a comparison and gets "not compared" or no flag is an error
- [x] R1.3 a suspect whose server is the reference returns without a flag, breaking settled(): flag Accept "not probed: the reference itself"; settled() logs accurately when nothing was tagged
- [x] R1.4 the "varies" cell checks the blocker per server, not per family: check it per family
- [x] R1.5 connEnd compares err.Error() (with addresses and ports), so identical failures never compare alike: compare by errno
- [x] R1.6 the upstream tell can't be turned off: module setting upstreamTell "flag" (default) or "report", documented in doc.go
- [x] R1.7 "varies" docs (lab.md, results_test.go, RESULTS.md header) still say partial fails; a varies key on a non-"(reference)" row is fatal; doc.go: udp's exemption chance is per link-hour
- [x] R1.8 the matrix never shows the prober's TLS comparison or the upstream tell
- [x] R1.9 a dropped new-flow snapshot silently clears an entry of the tell: censorRun.healthy fails on any unnoticed snapshot
- [x] R1.10 the OpenVPN probe keeps state in a package-level map keyed by a formatted pointer: read the node's state
- [x] R1.11 nits: probe helpers into probe.go, parseTimeout placement, endpoints.go → blockedservers.go, Flow.initiator comment, slice expression, nginx packages in lab/Dockerfile, split TestProberSettings, JA3S GREASE comment

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): prober covers the server-side fingerprint and the upstream-connection tell
- 2026-10-15 docs (backlog grooming): owns server JA3S/JA4S computation (TP-032 keeps client fingerprints and whitelist)
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-11-07 notes (owner's MVP cut): the JA3S/JA4S comparison's place on the MVP path is open
- 2026-11-07 notes: the server-hello comparison stays on the MVP path (owner, 2026-11-07)
- 2026-11-08 notes: the lab camouflage target the prober and server-hello comparison point at is built in TP-201
- 2026-11-09 backlog → in-progress, owner: agent-tp-026
- 2026-11-09 impl: lab/censor gains fully-encrypted (Wu et al.'s five exemptions on a connection's client's first data, TCP stream start and UDP first datagram; drop pinned, or tagOnly for the prober), prober (passive+active: replayed, random 3/16/49/221/1000-byte and own-TLS-handshake probes compared with a reference site; the upstream tell; a found-out server blocked by address and port; UDP suspects flagged Accept "not probed") and server-hello (JA3S, JA4S, version, cipher, extension order, ALPN of a connection's ServerHello against the site's answer to the same ClientHello, the site by name from a sites setting); Flow.Initiator; helloMessage reads ServerHellos too
- 2026-11-09 matrix: cases fully-encrypted, active prober and server-hello (the last two in lab.Upstream with nginx as the camouflage site; cells with an active module probe twice and score the probe after its verdicts, censorCase.settle; their cells quote the module's verdict); reference row random-tcp (socat echo fed random bytes); the https control row now serves nginx (same server and settings as the camouflage site); lab/Dockerfile pins nginx 1.22.1-9+deb12u10 and adds socat
- 2026-11-09 vantage: the brief said the lab censor isn't on the entry's uplink, but lab.Upstream (TP-089) puts the camouflage target behind the router and TestCensorSeesUpstream shows the entry's connection to it crosses the censor; the upstream tell is implemented on what the censor sees there (a connection from the probed address to the site during every probe), doc.go says when a real censor has that vantage; timing is reported in the verdict, not judged (lab round trips are sub-millisecond)
- 2026-11-09 tests: unit (lab/censor) TestLooksFullyEncryptedExemptions, TestFullyEncryptedFlagsRandomNotHTTPS, TestFullyEncryptedJudgesTheClientOnly, TestFullyEncryptedTagOnly, TestServerHelloFingerprints (FoxIO's JA4S example t130200_1301_234ea6891581), TestServerHelloReading, TestServerHelloDifferences, TestServerHelloComparesWithTheSite, TestProberTellsEchoFromWebServer, TestProberComparesTLS, TestProberUpstreamTell, TestProberTagsListedDestinations, TestProberOnTheEngine, TestProberSettings; lab TestFullyEncryptedRandomNotHTTPS, TestProberTellsEchoFromNginx, TestServerHelloAgainstTheSite
- 2026-11-09 mutations, each killed by the tests named: set bits <=3.4→<3.4 and >=4.6→>4.6, printable-prefix rule off, half printable >→>=, printable run >20→>=20, TLS/HTTP rule off, TLS minor <=9→<=10 (TestLooksFullyEncryptedExemptions); never blocks (TestFullyEncryptedFlagsRandomNotHTTPS); servers judged, UDP initiator always true, TCP client bit set on SYN-ACK (TestFullyEncryptedJudgesTheClientOnly); reactions always alike (TestProberTellsEchoFromWebServer, TestProberOnTheEngine); upstream tell off, upstream source ignored (TestProberUpstreamTell); TLS differences ignored, negotiated ALPN ignored (TestProberComparesTLS); blocked servers never blocked (TestProberTellsEchoFromWebServer, TestServerHelloComparesWithTheSite); prober tags nothing (TestProberTagsListedDestinations); hello differences never, extension order ignored (TestServerHelloDifferences); JA4S extensions sorted, JA3S keeps GREASE (TestServerHelloFingerprints); server-hello never flags a mismatch (TestServerHelloComparesWithTheSite)
- 2026-11-09 lab runs (make lab-gotest PKG=./lab): the three lab tests pass; TestCensorMatrix's new cells (every row × off, fully-encrypted, active prober, server-hello) all as expected: udp, wireguard and random-tcp fail fully-encrypted, openvpn udp/tcp and https pass it; random-tcp and openvpn-tcp fail the prober, https passes it (nginx answers every probe and handshake as the camouflage site's does); every row passes server-hello (https matches the site)
- 2026-11-09 make lint, make test green
- 2026-11-09 out of scope: TP-087's branch edits this ticket's backlog copy (a Notes line on TP-201's target), so merging it after this one conflicts on the ticket's path; nginx 1.22 leaves TLS 1.3 out unless ssl_protocols says so, which TP-201's camouflage target needs (startNginx sets it); the prober attributes an upstream connection by the probed source address only, so an entry whose uplink leaves by the other family isn't matched (doc.go)
- 2026-11-09 full make lab-test on 89fe9eb caught wireguard × fully-encrypted partial (IPv6 crossed): a WireGuard initiation ends in mac2's 16 zero bytes, about 3.47 set bits per byte, and Wu et al.'s first exemption passes about one in four (TestFullyEncryptedWireGuardInitiationByChance: 557 of 2000); the censor is unchanged, the matrix gained censorCase.varies (any result accepted and labelled with why, a blocked family still blamed on the blocker), doc.go says so; thinkpol udp's first datagram is exempt only by six printable bytes first, about 1 in 400
- 2026-11-09 merged origin/rewrite (TP-087 in; this ticket's backlog copy deleted, its Notes and Log line carried over); make lint, make test green on 4f8531c
- 2026-11-09 lab commit 4f8531c: full make lab-test (GOFLAGS=-p=2 LAB_P=1, exclusive CPU lock): the lab/ phase passed, TestCensorMatrix complete, lab/RESULTS.md regenerated (wireguard × fully-encrypted failed this run, labelled varies); the node phase failed once in TP-087's internal/dataplane/transport/reality TestConformance/ShapingRefused/2 ("reality: TLS handshake: EOF"), which passed 3 of 3 re-run alone (make lab-gotest PKG=./internal/dataplane/transport/reality RUN=TestConformance COUNT=3): a flake in code this ticket doesn't touch, reported, not fixed here
- 2026-11-09 not verified: reality's rows (TP-201) against these modules; RESULTS.md quotes lab-internal addresses, which change every run
- 2026-11-09 in-progress → review
- 2026-11-09 review → has-errors (round 1 findings R1.x)
- 2026-11-09 R1 fixes (agent stopped on 2026-11-09 at 02287bd, continued 2026-11-12): R1.1 the prober's passive half tags a TCP suspect only once its client's first bytes are settled (helloSettled: a whole ClientHello, bytes that can't start one, or retainBytes), the prober probes only what it tagged, an incomplete or other-name hello gets its own reason; R1.2 censorCase.verdictSays + verdictMisses: a prober or server-hello cell whose verdict lacks the comparison ("not compared", no flag) is an error; R1.3 a suspect to the reference is flagged Accept "not probed: the reference itself", settled() logs "no module tagged" when nothing was; R1.4 blockedBy blames the blocker per family that didn't cross (both for udp, whose overlays share one underlay); R1.5 connEnd names a failure by its errno alone; R1.6 prober setting upstreamTell "flag" (default) or "report", doc.go; R1.7 lab.md, results_test.go, RESULTS.md header say only a varying row may be partial, a varies key on a non-reference row is fatal, doc.go: udp's exemption is per link-hour and shared by both families (the connection id doesn't depend on the address), 1 in 383; R1.8 the https row asks for the camouflage site's name (TLS comparison and server-hello run on it), new reference row relay-tcp (server-1 splices to the site, lab.Upstream in every cell) shows the upstream tell; R1.9 the engine logs EventUnnoticed for a snapshot an active module missed, censorRun.healthy fails on one; R1.10 the OpenVPN probe asks pgrep on device-a whether its clients run; R1.11 probe.go, parseTimeout in verdicts.go, endpoints.go → blockedservers.go, Flow.initiator comment, answerKept slice, lab/Dockerfile installs nginx only (nginx-light is nginx plus an unused echo module), TestServerHelloSettings split out, GREASE comment
- 2026-11-09 owner decision (2026-11-09): the upstream tell is reported, not gated: milestones.md M2 row, lab.md's censor list and RR31 say so; TP-201's reality rows use upstreamTell "report"
- 2026-11-09 tests: TestProberWaitsForTheWholeHello (a 1.8 KB ClientHello with an X25519MLKEM768 share split over two segments through the engine), TestConnEnd, TestProberReportsUpstreamTell, TestServerHelloSettings, TestBlames, TestVerdictMisses; TestProberTellsEchoFromWebServer gains the reference suspect, TestEngineSlowActiveNeverStalls the unnoticed log line
- 2026-11-09 mutations, each killed by the test named: tag on the first segment (TestProberWaitsForTheWholeHello); no flag for a suspect to the reference (TestProberTellsEchoFromWebServer); connEnd compares err.Error() (TestConnEnd); upstreamTell report ignored (TestProberReportsUpstreamTell); unnoticed snapshot not logged (TestEngineSlowActiveNeverStalls); blame the whole server, not the family (TestBlames); verdictMisses never errs (TestVerdictMisses)
- 2026-11-09 make test green on edb6453; make lint: vet and golangci-lint (darwin, linux, windows), the android build, nocgo and buf green, govulncheck fails on GO-2026-6859 (net/http, fixed in go1.26.11; go.mod's toolchain go1.26.10 is rewrite's too): out of scope, reported
- 2026-11-09 lab commit edb6453: full make lab-test (GOFLAGS=-p=2 LAB_P=1, exclusive CPU lock): the lab/ phase passed, TestCensorMatrix complete with no error cell, lab/RESULTS.md regenerated (https × active prober runs the TLS comparison and passes; relay-tcp × active prober fails on the upstream tell, 7 of 7; https and relay-tcp × server-hello match the site; wireguard × fully-encrypted passed this run, labelled varies); the node phase failed only in TP-087's internal/dataplane/transport/reality TestConformanceShaped/random/ShapingRefused/6 ("reality: TLS handshake: EOF"), which failed again alone in 1 of 3 runs (make lab-gotest PKG=./internal/dataplane/transport/reality RUN=TestConformance COUNT=3, ShapingRefused/8): intermittent in code this branch doesn't touch, not fixed here
- 2026-11-09 not verified: reality's own rows (TP-201) against these modules with upstreamTell "report"
- 2026-11-09 has-errors → in-progress (R1.1–R1.11 fixed and ticked)
