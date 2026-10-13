---
id: TP-061
title: "Security hardening from the independent code review (2026-10-13)"
milestone: M1
area: security
repo: thinkpol-vpn
size: M
depends_on: []
refs: [DESIGN#routing-rules-and-dns, DESIGN#desktop-client]
owner: "agent-hardening"
branch: "tp-061-security-hardening"
---

## Goal
The findings of the independent security code review of 2026-10-13 are fixed or written down as decisions: no known-vulnerable module in reachable code (and a lint step that keeps it so), a resolver that only accepts an upstream's answer from the server it asked, no integer conversion from wire or user input that can panic, a dev-only secrets seed that can't end up in a real map, and the review's smaller notes recorded where the code lives.

## Scope
- **Dependencies.** `google.golang.org/grpc` ≥ 1.83.1, `golang.org/x/net` ≥ 0.60.0, and any other module govulncheck flags in reachable code. A `make vulncheck` target (govulncheck, pinned in `make tools`), run from `make lint`.
- **Resolver upstreams** (`internal/dataplane/dns`, `exchange`): one connected UDP socket per upstream query, so the kernel picks a random ephemeral source port and only the asked server's address and port are delivered; the transaction-ID check stays; no answer from another server is accepted for that query; truncation, or a reply that fails the ID or question check, falls back to TCP. The remaining window is written down at the ID check. Tunnel and direct socket controls (marks, TUN binding) unchanged.
- **Integer conversions.** `TailLogs` clamps `lines` through uint64 before converting to `int`; a sweep of other conversions from wire or user input (proto getters, length fields, offsets) fixes any that could panic or go negative; the local API's gRPC server recovers handler panics.
- **Insecure secrets seed.** `dev map build -insecure-secrets-seed` is refused unless the spec declares `lab: true` (top level); the map itself is unchanged (no wire change); help text and a test.
- **Notes in code.** Local API client: the socket directory is the trust anchor. `blobs/serve.go`: the plan is the access control, by construction if cheap, else documented precisely. udp transport `wire.go`: send time is uint32 seconds, wraps in 2106, and `fresh()` tolerates it (verified).
- **DESIGN.md.** One sentence: the udp transport authenticates with an AEAD (XChaCha20-Poly1305 under credential-derived keys); NaCl sealed boxes are only used for map sections.

## Out of scope
- The review's macOS/Windows kill-switch note (TP-021, TP-047).
- DoT or DNS-over-TCP-only upstreams.

## Acceptance
- [x] govulncheck before/after recorded in Notes; after: no vulnerability in reachable code (darwin, linux, windows)
- [x] `make vulncheck` exists, govulncheck pinned in `make tools` (`GOVULNCHECK_VERSION`, in the tools stamp), run from `make lint`
- [x] resolver: a spoofed answer from a different source is ignored and the real one is used; a matching answer from the right server is accepted; truncation and spoof-suspect replies fall back to TCP (tests): `internal/dataplane/dns/upstream_test.go` `TestASpoofedAnswerFromAnotherSourceIsIgnored`, `TestTheAskedServersAnswerIsAccepted`, `TestWhatDoesntAnswerTheQueryGoesOverTCP` (wrong ID, wrong question, not a response, garbage, too big), `TestATruncatedAnswerGoesOverTCP`; the ID subtest fails if a mismatch is skipped instead of ending the UDP try
- [x] `TailLogs` clamps; sweep findings listed in Notes; local API gRPC server recovers panics (test): `TestAPanickingHandlerFailsOnlyItsCall` (unary and stream), `TestTailLogsTakesAnyLineCount`
- [x] `dev map build -insecure-secrets-seed` refused without `lab: true` in the spec, accepted with it (test); help text updated: `internal/devmap` `TestASecretsSeedNeedsALabSpec` (also: `lab: true` leaves the planned contents identical), `cmd/thinkpol` `TestDevMapBuildSeedNeedsALabSpec`
- [x] the notes are in code comments; DESIGN.md sentence on the udp transport's AEAD
- [x] `make lint`, `make test`, race on touched packages, and `make lab-gotest PKG=./internal/dataplane/dns/...` pass; also in the lab: `TestDNSFollowsTheRules`, `TestEgressThroughAnExit` (builds with the seed from `lab/maps/egress.yaml`, now `lab: true`), `TestBlobDistribution`, `TestLocalAPI`

## Notes
- **govulncheck before** (v1.9.0, `rewrite` at 70156fd, go1.25.0): "Your code is affected by 30 vulnerabilities from 1 module and the Go standard library." Modules: `google.golang.org/grpc@v1.82.0` GO-2026-6443 (fixed 1.82.2), GO-2026-6348 (fixed 1.83.1), GO-2026-6061 (fixed 1.82.1); `golang.org/x/net@v0.57.0` GO-2026-6617, -6612, -6611, -6603 (fixed 0.60.0). Standard library (go1.25.0): 23 more in net/http, net/textproto, net/url, net, crypto/tls, crypto/x509, encoding/asn1, html/template (GO-2025-4007 … GO-2026-6613), the newest fixed only in go1.26.9.
- **govulncheck after** (`make vulncheck`, each of darwin/linux/windows): "No vulnerabilities found. Your code is affected by 0 vulnerabilities." It still lists one module-level finding our code doesn't call: GO-2026-5932, `golang.org/x/crypto/openpgp` (unmaintained; no fix; we don't import it).
- **Go 1.26.** x/net ≥ 0.60.0 needs Go 1.26, so `go.mod` moves to `go 1.26.0` with `toolchain go1.26.9` (the first release with every reachable stdlib fix); `GOTOOLCHAIN=auto` fetches it. grpc 1.84.0, x/net 0.61.0, x/crypto 0.58.0, x/sys 0.49.0. README, AGENTS.md and ORCHESTRATION.md updated. The newer toolchain let staticcheck prove the unsupported-OS stubs always fail (SA4023 at their callers on darwin/windows): `netcfg.New`, `agent.supported`, `localapi.Listen` and `callerOf` stubs now return package-level error variables. **Merge note:** TP-019 changes the build line and signature of `internal/agent/platform_other.go` (`supported(Mode)`); whichever merges second keeps both (the variable and TP-019's signature).
- **`make vulncheck`** fetches the vulnerability database from vuln.go.dev on every run (a few seconds per OS), so `make lint` needs the network; documented in the Makefile and README.
- **Resolver.** miekg/dns's `Exchange` already dialed a connected UDP socket per query, so the kernel was already filtering sources. What it did wrong: it skipped datagrams with a wrong ID and kept reading until the timeout, so a guesser who hit the port got unlimited ID guesses, and it never checked the question. Now `exchangeWith`/`exchangeUDP` (`dns/upstream.go`) does the UDP side itself: one connected socket per server tried, a fresh ID per try, a source check (belt and braces), and ID + opcode + QR + question checks. Any datagram from the server that isn't the answer ends the UDP try and the query goes over TCP (also checked), the same as on truncation. The remaining window is in the comment at the check: an off-path attacker gets one 16-bit guess per query, and only after hitting the ephemeral port. An on-path attacker can still answer first (that would take DoT or DNSSEC). Tunnel-bound queries go inside the tunnel. Socket controls go to the `net.Dialer` exactly as before.
- **Sweep** (`int(` on proto getters, wire lengths and offsets, plus gosec G115 over every OS, triaged by hand). Fixed: `TailLogs` (`int(min(uint64(lines), MaxInt32))`); the client's `uint32(lines)` silently wrapped above 2^32 (now clamped); `udp` `fresh()` did **not** tolerate the 2106 wrap: the sent time was decoded as `time.Unix(uint32)`, so after the wrap every datagram would read as from 1970 and be dropped. It now compares mod 2^32, signed, with no wire change (`TestFreshnessHoldsAcrossTheWrap`). Checked and safe: shaping (decoded through `shaping.Check` before any conversion or index), blobs offset (bounds-checked before slicing), lists blob counts, ipc datagram/stream headers, path probe frames (`len == probeSize`), logring `Since` (seq clamped to the live range), netmap enum casts (clamped to 255 = unknown), supervisor options (validated). No narrowing conversions in `cmd/`.
- **Panic recovery.** The local API server is `grpckit.NewServer`, whose standard chain (outermost, before the policy interceptors) recovers panics in unary and streaming handlers and returns a masked Internal. No extra interceptor was needed; the test proves it on this server. Goroutines a handler starts are not covered (there are none).
- **Blobs: the plan is the access control, by construction.** `Update` builds `peerOf` (overlay address → peer) under the same lock as the plan. `peerOfLocked` is the one place access is decided, asked at admission and again before every 16 KiB chunk, so a peer the new map drops gets nothing more, whatever order the tunnel and the service take the map in (`TestAPeerDroppedFromThePlanIsServedNoMore`, which fails without the per-chunk check). Package doc updated.
- **Local API client:** the trust-anchor note is at `Dial`: the socket directory (`ownDir`, `checkParent`) is all that keeps another process from posing as the service; a path given by hand is trusted as given.
- **`lab: true`** is read as written (no `${NAME}`), so the spec itself has to say it. It only gates `InsecureSeededSecrets(spec, seed)`, the one way to get seeded secrets, and nothing goes into the map. `reference.yaml` documents it; `lab/maps/egress.yaml` (the only seeded build) declares it.
- **DESIGN.md** "Transports": one sentence. udp's datagrams are sealed with an AEAD (XChaCha20-Poly1305 under a per-direction key derived from the link's credential), not a NaCl sealed box; sealed boxes are only for what is sealed to a public key, such as map sections.

## Review findings
From the orchestrator's review, 2026-10-13. One fix pass, then merge.
- [ ] 1. `dns/upstream.go`: the source check compares the AddrPort with its zone. resolved writes `fe80::1%2` (numeric) while Go reports `%eth0`, so every link-local upstream's reply is rejected (timeout, no TCP fallback). Compare without the zone (Unmap + WithZone("") on both, plus the port) or rely on the connected socket; test with a numeric-zone server.
- [ ] 2. Windows: an over-size datagram (WSAEMSGSIZE) maps to errNotAnAnswer (TCP fallback), not to skipping the server.
- [ ] 3. `blobs/serve.go`: when stillPeer fails, abort the connection (SetLinger(0), a reset) instead of a graceful close, so buffered data isn't delivered; narrow the comment to "within one map transition, for an address reassigned in the same map".
- [ ] 4. Makefile: run vulncheck for android too.
- [ ] 5. Note in the ticket: rebuilding the tools with an older local Go fails closed; document that `make tools` needs Go ≥ 1.26 or `GOTOOLCHAIN=auto`.

## Log
- 2026-10-13 created in in-progress — owner: agent-hardening, branch: tp-061-security-hardening
- 2026-10-13 in-progress → review — all acceptance met; lint, test, race and the lab checks above pass
- 2026-10-13 review → has-errors — 5 findings from the orchestrator's review, see Review findings
- 2026-10-13 has-errors → in-progress — owner: agent-hardening, fixing review findings
