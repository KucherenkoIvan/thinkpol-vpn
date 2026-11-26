# thinkpol-vpn — The reality ClientHello as a transport option

A design note: the `reality` link's ClientHello becomes a choice in the map, with a classical X25519-only profile beside today's hybrid one. Proposed 2026-11-26, **awaiting the owner's approval**: no ticket is filed and nothing is built until then. The entry point is [DESIGN.md](../../DESIGN.md); the transport is [`reality`](../../internal/dataplane/transport/reality/doc.go); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

**The problem.** The dialer sends uTLS's `HelloChrome_Auto` (Chrome 133, `dialer.go:61`), whose key share carries X25519MLKEM768 (1,216 bytes: `hello.go`'s `mlkem768KeySize` plus the X25519 half). The hello's record is 1,725–1,821 bytes (table below), so it always takes two TCP segments: a 1,500-byte MTU leaves 1,460 bytes of payload over IPv4, 1,448 with TCP timestamps, 1,440 over IPv6. On a residential network in Russia in 2026, public reports describe stock REALITY clients sending this hello hanging, and the same profile with a classical X25519-only share connecting; a well-known client added a `key_share: classical` option for it, and fragmenting or padding the hello reportedly doesn't help. thinkpol has no classical fallback: the listener refuses a hello without X25519MLKEM768 before its X25519 share (`hello.go:171`), because REALITY's server does too.

## The option

- **Field and values.** The existing `fingerprint` field of `RealityDialSettings` (`proto/thinkpol/transport/v1/reality.proto`, field 3) takes a second value: `chrome` (empty means it too: today's hello, the default) and `chrome-classical`. No new field: an old dialer already refuses a value it doesn't know (`settings.go:116`), which is "refuse, never weaken" for free.
- **`chrome-classical` is today's Chrome spec with two edits:** X25519MLKEM768 removed from both `key_share` and `supported_groups`, and BoringSSL's padding extension added, as uTLS's classical `HelloChrome_120` spec has it. That is what Chrome sends with post-quantum key agreement turned off (its `PostQuantumKeyAgreementEnabled` policy for managed machines). Removing the group from `supported_groups` too matters: a target that prefers the hybrid group and sees it offered without a share answers with a HelloRetryRequest, which REALITY can't imitate (the module's `tls.go:363-370` requires an X25519 or hybrid server share and gives up on anything else), so the dial would fail. The spec is derived from `HelloChrome_Auto` at run time, so a uTLS bump moves both profiles together.
- **Firefox, Safari, iOS: later, not now.** uTLS v1.8.2's `HelloFirefox_Auto`, `HelloSafari_Auto` and `HelloIOS_Auto` are Firefox 120, Safari 16.0 and iOS 14: years-old versions, and current releases of those browsers send a hybrid share too. They would add a stale-version tell, not camouflage. Revisit when uTLS carries current specs.
- **Which end.** The client sends it; the listener accepts both. The seal is keyed with the standalone X25519 share in either profile (`clientShare` in `dialer.go`), so authentication is unchanged. What a classical link loses is the outer TLS's post-quantum key exchange, and the WireGuard tunnel inside is classical (Curve25519) anyway, so payload confidentiality doesn't change.
- **Listener rule.** A hello with X25519MLKEM768 keeps today's rule exactly (the hybrid before any X25519 share, each at most once). A hello with no hybrid share is accepted only with exactly one 32-byte X25519 share. The standalone listener, the supervisor's router and the worker's handoff all parse with `parseHello`, so one change covers all three.
- **No listener setting.** Accepting classical is visible only to someone holding a valid short id: a prober's hello fails the seal and is spliced to the target either way. A per-listener opt-in field would gate nothing a censor can see (open question 2).
- **Rollout.** A listener that can't accept a classical hello must never get a link that sends one. Per the transports rule, the controller puts `chrome-classical` into a link only once the listener's node reports that its `reality` accepts it and the dialer's node reports that it sends it, in the capabilities agents report. Until the controller exists, `devmap` builds both ends' maps for one build, so that holds by construction. The parsers of `reality`'s settings also start refusing unknown fields (as `shaping` does with `GetUnknown`), so a later field never meets a node that would silently ignore it.

## The server side

**With the module as pinned, a listener can't accept a classical hello.** `github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0` is the commit that added the rejection ("Reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before optional X25519"). In its `tls.go:214-238`, `Server` takes the X25519 half of X25519MLKEM768 (`peerPub2`) and an optional standalone X25519 after it. At `tls.go:233-234`, `if peerPub2 == nil { break }` leaves before any seal is opened, so a classical hello is spliced to the target as a stranger and the dial fails with `ErrNotAuthenticated`. The handshake itself would work: REALITY answers with the group the target chose (`handshake_server_tls13.go:106-129`), and X25519 is one it handles. The upstream repository's head (2026-11-08) keeps the check. thinkpol can't hand REALITY a rewritten hello either: the hello is the seal's additional data and in the TLS transcript.

| Option | Cost |
|---|---|
| **A. Pin the parent commit**, `e1986a4` (2026-09-08 04:58 UTC, 83 minutes earlier) | Loses only the rejection itself: that commit changes `tls.go` alone (+18 −8). The pin can't move past `8cdf7bf` without losing classical; it is already held there by the Go 1.27 requirement of the commits after it (`go.mod:18`'s comment) |
| B. A fork as its own public MPL-2.0 module (a `replace` in `go.mod`), the check made a `Config` switch | No licence problem, since the fork stays a separate module and never enters this MIT tree, but every upstream fix is ours to merge from then on |
| C. The listener completes a classical handshake by other means | REALITY's server rewritten in the MIT tree: the ServerHello and record imitation, the HMAC certificate. Weeks of work, and the result risks being a derived work of what it imitates. Not worth it |
| D. A per-listener choice | Not possible with the unmodified current pin. With A or B it comes free: thinkpol's own gate decides before REALITY runs |

**Recommended: A now, B when the pin must move** (the Go 1.27 bump). Plainly: keeping classical while tracking upstream past `8cdf7bf` needs a fork.

## What a censor sees

Sizes measured from uTLS v1.8.2's specs, each built 500 times with a 15-byte server name; the spread is the random length of Chrome's GREASE ECH payload. Bytes are the TLS record, header included:

| Profile | Record | Segments (1,448-byte MSS) |
|---|---|---|
| `chrome` (`HelloChrome_Auto`, Chrome 133, hybrid) | 1,725–1,821 | 2 |
| `chrome-classical` (as above) | 517–599 | 1 |
| for comparison: `HelloChrome_120`, `HelloFirefox_Auto`, `HelloSafari_Auto` / `HelloIOS_Auto` | 517–599, 663, 517 | 1 |

- **The classical hello is an outlier.** Chrome has sent a hybrid share by default since 2024. A Chrome-shaped hello without it marks an old Chrome, or a managed one with the policy off, or a tool that imitates Chrome. JA4 doesn't see the difference: its parts are the cipher and extension sets and the signature algorithms, never the groups or the key shares. JA3 includes `supported_groups`, so its value changes, but Chrome's extension order is shuffled and plain JA3 already varies per connection. A censor that parses the hello anyway, as one with an SNI blocklist does, could match "Chrome's extension set without the hybrid group" with one cheap rule. We know of no public report of a censor doing that in 2026.
- **The hybrid hello is stalled outright** on some networks, which is worse than a tell: the link doesn't come up at all. A link chooses between a rarer hello and one that doesn't pass.

**Proposed row, RR68** (Transports and probing; Breaks C2):

> | RR68 | A classical-share Chrome hello is rare | `reality` links whose map sets `fingerprint: chrome-classical` | The ClientHello is Chrome's without X25519MLKEM768 in its key shares and groups, which current Chrome sends by default: a censor reading the hello can single out the link's flows (an old or policy-managed Chrome, or an imitation) | C2 | Opt-in per link, for networks that stall the 1.7 KB hybrid hello: a rarer hello is better than no link. The default stays the hybrid hello | (the ticket that builds it) | [`reality`](internal/dataplane/transport/reality/doc.go) |

## How a member chooses

**Per link, in the map (C3).** A client → entry link belongs to one device, so a per-link choice is already per device. The space's admin sets `chrome-classical` on the links of devices on networks that stall the hybrid hello.

- **Per-device override: rejected.** It would make a second source of truth beside the map for what goes on the wire. The configuration levels only narrow one another (configuration.md), and a different hello isn't a narrowing.
- **Automatic fallback (hybrid, then classical): rejected.** Every failed dial would show a censor a stalled hybrid hello followed by a classical hello from the same device to the same address, which is a pattern of its own. A censor that stalls on purpose could also steer every client to the rarer, more markable profile: a downgrade under the censor's control.

## The lab

- **The censor module `hello-stall`** (passive, in `lab/censor`): on a TCP flow whose first TLS record is a handshake record longer than the first segment's payload, or longer than its `maxRecord` setting when one is set, it accepts that first segment and drops every later packet of the flow both ways, pinned. That is a stall, not a reset, as described above. It decides on the first segment from the record header alone, with no reassembly.
- **The matrix.** A new row `reality-classical` (the reality row with `fingerprint: chrome-classical`), and a case `hello-stall` in `censorCases` expecting `reality` to fail and `reality-classical` to pass. Expectations for the other rows are measured when the module lands. The row's cost is a full row through every case (open question 4).
- **Conformance per profile.**
  - `TestConformance`, `TestConformanceLateTable` and `TestConformanceShaped` run once per profile.
  - A hello-shape test: `chrome-classical` differs from `chrome` only by the hybrid group (key share and groups) and the padding extension, so its JA4 is the same; it fits one segment; it has exactly one X25519 share.
  - `TestReadShare` gains the classical cases: one X25519 share is accepted; two X25519 shares, X25519 before the hybrid, the hybrid twice, or no X25519 at all are refused.
  - Against the lab's nginx target: a classical hello gets a ServerHello, never a HelloRetryRequest.
  - `TestStockXray` gets a classical subtest that asserts what the lab's pinned Xray build does with it (refusal from about v26.9.8) and names that build, so an Xray bump that changes the answer fails the test.

## Out of scope, later

- ECH: REALITY can't offer the target's ECH configuration.
- Other transports' hellos (`tls`, node-to-node, after the MVP).
- Firefox, Safari and iOS profiles, until uTLS has current specs.
- Choosing a profile by network (a device that roams between a stalling network and a clean one).
- Fragmenting the hello, reportedly useless against this stall.

## Open questions for the owner

1. **Server option A (pin `e1986a4`) or B (fork now)?** *Recommended: A*, B at the Go 1.27 bump.
2. **Should every listener accept classical, or should there be a per-listener opt-in field?** *Recommended: every listener.* Acceptance is invisible without a short id, and a field adds rollout state for no camouflage.
3. **Should the classical profile drop the hybrid group from `supported_groups` too, or only from `key_share`?** *Recommended: both*, as Chrome with the policy off does. A share-only variant risks a HelloRetryRequest that REALITY can't imitate.
4. **A full matrix row for `reality-classical`, or only a targeted lab test of `hello-stall` against both profiles?** *Recommended: the full row*, because the classical profile meets every censor the default does.
