# thinkpol-vpn — The reality ClientHello as a transport option

A design note: the `reality` link's ClientHello becomes a choice in the map, with a classical X25519-only profile beside today's hybrid one. Proposed 2026-11-26, **awaiting the owner's approval**: no ticket is filed and nothing is built until then. The entry point is [DESIGN.md](../../DESIGN.md); the transport is [`reality`](../../internal/dataplane/transport/reality/doc.go); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

**The problem.** The dialer sends uTLS's `HelloChrome_Auto` (Chrome 133, `dialer.go:61`), whose key share carries X25519MLKEM768 (1,216 bytes: `hello.go`'s `mlkem768KeySize` plus the X25519 half). Its record is 1,725–1,821 bytes, two TCP segments at any 1,500-byte MTU (1,448 bytes of payload with TCP timestamps). On residential networks in Russia in 2026, public reports describe stock REALITY clients sending this hello hanging, and the same profile with a classical X25519-only share connecting; a well-known client added a `key_share: classical` option for it, and fragmenting or padding the hello reportedly doesn't help. thinkpol's listener refuses a hello without X25519MLKEM768 (`hello.go:171`), because REALITY's server does too.

## The option

- **Field and values.** `RealityDialSettings`' existing `fingerprint` field (field 3) takes `chrome` (or empty: today's hello, the default) or `chrome-classical`. An old dialer already refuses a value it doesn't know (`settings.go:116`): "refuse, never weaken" for free.
- **`chrome-classical` is today's Chrome spec with two edits:** X25519MLKEM768 removed from both `key_share` and `supported_groups`, and BoringSSL's padding extension (21) added last, after the trailing GREASE extension, as uTLS's classical `HelloChrome_120` spec has it. Removing the group from `supported_groups` too matters: a target that prefers the hybrid group and sees it offered without a share answers with a HelloRetryRequest, which REALITY can't imitate (below). Derived from `HelloChrome_Auto` at run time, so a uTLS bump moves both.
- **Which Chrome it imitates.** The derived spec keeps Chrome 133's ALPS codepoint 17613; Chromes before post-quantum key agreement sent 17513. So the hello is that of Chrome 133–146 with the `PostQuantumKeyAgreementEnabled` enterprise policy off: the policy was supported in Chrome 116–146 and removed in Chrome 147 (April 2026), which has no switch at all ([Chrome Enterprise policy list](https://chromeenterprise.google/policies/post-quantum-key-agreement-enabled/); [Edge's copy of it](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/postquantumkeyagreementenabled): obsolete after 146). **No current Chrome sends this hello.**
- **Firefox, Safari, iOS: later.** uTLS v1.8.2's specs for them are Firefox 120, Safari 16.0 and iOS 14, years old; current releases send a hybrid share too.
- **Which end.** The client sends it; the listener accepts both. The seal is keyed with the standalone X25519 share in either profile (`clientShare`, `dialer.go:108-117`), so authentication is unchanged.
- **What a classical link loses: post-quantum confidentiality.** Today's outer TLS, when the target picks the hybrid group (REALITY answers with the group the target chose, `handshake_server_tls13.go:106-129`), hides the inner WireGuard handshake from an adversary who records now and decrypts later. A classical outer TLS doesn't. thinkpol sets no WireGuard preshared key, so once Curve25519 falls, a recorded classical flow is readable: outer TLS, the WireGuard handshake inside, and from it the payload.
- **Listener rule.** A hello with X25519MLKEM768 keeps today's rule exactly: the hybrid before any X25519 share, the hybrid at most once, and the first X25519 share wins (`readShare`, `hello.go:154`). A hello with no hybrid share is accepted with its first 32-byte X25519 share; a second X25519 share is not refused. That is the share REALITY at `e1986a4` takes too, so the gate and REALITY always key the seal with the same share. One change to `parseHello` covers the listener, the router and the handoff.
- **No listener setting.** Only a holder of a valid short id can see that a listener accepts classical: a prober's hello is spliced to the target either way (open question 3).
- **Targets that answer a classical hello with a HelloRetryRequest.** A target that prefers P-256 answers it with one; REALITY gives up on any server share other than X25519 or the hybrid (`tls.go:363-370`) and splices the connection to the target (`tls.go:442-457`), so every classical link to that entry fails silently. **Chosen: the listener's target check finds it.** verifyTarget (RR66) also sends the `chrome-classical` hello (uTLS, the dialer's own spec) per server name, and a HelloRetryRequest, or a ServerHello not on X25519, marks the profile unusable for that target: a diag line, the listener's status, and the capabilities its node reports, so the controller never puts `chrome-classical` on a link to it. A diag line alone would leave the link down with nothing on the member's side saying why. The cost: one more connection to the target per server name at each check and re-check, two per server name on a dual-stack start (RR66's count doubles).
- **Rollout.** The controller puts `chrome-classical` into a link only once both nodes' reported capabilities say the listener accepts it (and its target answers it) and the dialer sends it. Until the controller exists, `devmap` builds both ends' maps; that is safe only while every listener process those maps reach runs a build with this change: servers are updated before any map sets the value. `parseDial` keeps unknown fields today (`proto.Unmarshal`, `settings.go:101`), so a binary from before this change silently ignores a field it doesn't know. The settings parsers start refusing unknown fields (as `shaping` does with `GetUnknown`), which guards later fields only against binaries from this change on.

## The server side

**With the module as pinned, a listener can't accept a classical hello.** `github.com/xtls/reality v0.0.0-20260908062103-8cdf7bf9c7f0` is the commit that added the rejection ("Reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before optional X25519"). At its `tls.go:233-234`, `if peerPub2 == nil { break }` leaves before any seal is opened, so a classical hello is spliced to the target as a stranger. The handshake itself would work: X25519 is a group REALITY answers with. thinkpol can't hand REALITY a rewritten hello either: the hello is the seal's additional data and in the TLS transcript.

**The parent commit, `e1986a4`** (83 minutes earlier). GitHub's compare `e1986a4d31ca33c087a72ab4644aef1295693b69...8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8` shows one file, `tls.go`, +18 −8; the two module trees differ in nothing else. `e1986a4` is itself the detection fix (#36), which the pin keeps; auth, replay, splice and `record_detect.go` are untouched. Upstream's head `4a26e877` (2026-11-08) still refuses, and the commit after `8cdf7bf`, `3c98159`, is the Go 1.27 sync. At `e1986a4`, `tls.go:214-228` keys the seal with the first standalone X25519 share, else the X25519 half of the first X25519MLKEM768 share: exactly the dialer's `clientShare` rule (the standalone share, else the hybrid's half).

| Option | Cost |
|---|---|
| **A. Pin the parent commit `e1986a4`** | Loses only the rejection. The pin can't move past `8cdf7bf` without losing classical; the Go 1.27 requirement already holds it there (`go.mod:18`) |
| B. A fork as its own public MPL-2.0 module (a `replace`), the check made a `Config` switch | No licence problem (a separate module, outside this MIT tree), but every upstream fix is ours to merge |
| C. REALITY's server rewritten in the MIT tree | Weeks of work, and a likely derived work. Not worth it |

**Recommended: A now, B when the pin must move** (the Go 1.27 bump).

## What a censor sees

Sizes measured from uTLS v1.8.2's specs, each built 500 times with a 15-byte server name. Bytes are the TLS record, header included:

| Profile | Record | Segments (1,448-byte MSS) |
|---|---|---|
| `chrome` (`HelloChrome_Auto`, Chrome 133, hybrid) | 1,725–1,821 | 2 |
| `chrome-classical` (as above) | 517, 535, 567 or 599 | 1 |

The classical record takes four lengths because Chrome's GREASE ECH payload steps by 32 bytes. BoringSSL's padding rule (uTLS `BoringPaddingStyle`, `u_tls_extensions.go:1111`) pads only a hello of 256–511 bytes, up to 512, so only the 517-byte cohort (about 121 of the 500 builds) carries the padding extension; the other three carry the hybrid profile's extension set exactly.

- **The classical hello is an outlier.** Chrome has sent a hybrid share by default since 2024, and since Chrome 147 can't be told not to. A Chrome 133-shaped hello without it marks a managed Chrome 133–146, months out of date, or a tool that imitates Chrome.
- **JA4** hashes the cipher and extension ids (and the signature algorithms), never the groups or the key shares. The three cohorts without padding have the hybrid profile's JA4; the 517-byte cohort's differs, in the extension count and the extension hash. JA3 includes `supported_groups` and changes, but Chrome's shuffled extension order already varies it per connection. A censor that parses the hello anyway (an SNI blocklist does) could match "Chrome's extension set without the hybrid group" with one cheap rule; we know of no public report of one doing so.
- **The hybrid hello is stalled outright** on some networks: a link chooses between a rarer hello and one that doesn't pass.

**Proposed row, RR68** (Transports and probing; Breaks C2):

> | RR68 | A classical-share Chrome hello is rare, and not post-quantum | `reality` links whose map sets `fingerprint: chrome-classical` | (1) The ClientHello is Chrome 133's without X25519MLKEM768 in its key shares and groups, which only Chrome 133–146 with the `PostQuantumKeyAgreementEnabled` policy off sends; no current Chrome does. Seen by the censor on the path, which can single out the link's flows, and, from the entry's address (REALITY's MirrorConn forwards it), by the camouflage site's operator and any CDN logging JA3/JA4 in front of it. Switching a link's profile shows "same device, new hello" once. (2) The outer TLS is classical, and WireGuard has no preshared key: a flow recorded now becomes readable, payload included, to whoever records it once Curve25519 falls | C2 (PRD.md states no post-quantum or payload-confidentiality requirement, so (2) breaks none) | Opt-in per link, for networks that stall the 1.7 KB hybrid hello: a rarer hello is better than no link. A WireGuard preshared key would close (2) (open question 5) | (the ticket that builds it) | [`reality`](internal/dataplane/transport/reality/doc.go) |

## How a member chooses

**Per link, in the map (C3).** A client → entry link belongs to one device, so per link is already per device.

- **Per-device override: rejected.** A second source of truth beside the map for what goes on the wire; configuration levels only narrow one another (configuration.md), and a different hello isn't a narrowing.
- **Automatic fallback (hybrid, then classical): rejected.** Each failed dial would show a censor a stalled hybrid hello, then a classical one from the same device to the same address: a pattern of its own. A censor that stalls on purpose could also steer every client to the rarer profile: a downgrade it controls.

## The lab

- **The censor module `hello-stall`** (passive, in `lab/censor`): when a flow's first TLS record is longer than its first segment's payload (or than `maxRecord`, when set), it passes that segment and drops every later packet of the flow both ways. It decides on the packet, from the record header's length against the segment's payload, not on the reassembled Stream; the queue hands it MTU-sized packets, since NFQUEUE completes GSO first (`lab/censor/doc.go:52`).
- **What it can't tell apart.** At MTU 1500 it separates the two profiles, but it stands equally for a censor that stalls on segment count, on byte size, on group `0x11ec` or on destination IP ranges. So the lab can't prove the classical profile passes a real network.
- **The matrix.** A new row `reality-classical` (the reality row with `fingerprint: chrome-classical`), and a case `hello-stall` in `censorCases` expecting `reality` to fail and `reality-classical` to pass. Other rows' expectations are measured when the module lands (open question 4).
- **Conformance per profile.**
  - `TestConformance`, `TestConformanceLateTable` and `TestConformanceShaped` run once per profile.
  - A hello-shape test: `chrome-classical`'s extension set, padding aside, equals `chrome`'s; its groups and key shares differ only by the hybrid group; a 517-byte hello carries padding as its last extension, after the trailing GREASE, and a longer one carries none; it fits one segment; its first X25519 share is the one `clientShare` keys. It asserts no single JA4 across classical hellos.
  - `TestReadShare` gains the classical cases: one X25519 share is accepted; with two, the first is the one returned; X25519 before the hybrid, the hybrid twice, or no X25519 at all are refused.
  - The target check against the lab's nginx target: the classical hello gets a ServerHello on X25519; against a target configured to prefer P-256, it gets a HelloRetryRequest and the profile is reported unusable.
  - `TestStockXray` gets a classical subtest asserting what the pinned Xray build does with it (refusal from about v26.9.8), so a bump that changes the answer fails.
- **On a device (acceptance).** One connect with each profile, on the owner's device, from a network that stalls the hybrid hello, at the M2 device sitting: `chrome` stalls and `chrome-classical` connects.

**Docs to change when built:** the `reality` package doc (its Settings section says "only chrome so far", `doc.go:283`), RR66 (the extra check hello), the new RR68, `lab/README.md` and the censor package doc for `hello-stall`.

## Out of scope, later

- ECH (REALITY can't offer the target's ECH configuration).
- Other transports' hellos (`tls`, node-to-node, after the MVP).
- Choosing a profile by network.

## Open questions for the owner

1. **Build `chrome-classical` although no current Chrome sends that hello?** *Recommended: yes, opt-in per link.* A censor can single it out, but on a stalling network the alternative is no link.
2. **Server option A (pin `e1986a4`) or B (fork now)?** *Recommended: A*, B at the Go 1.27 bump.
3. **Should every listener accept classical, or should there be a per-listener opt-in field?** *Recommended: every listener.* Acceptance is invisible without a short id.
4. **A full matrix row for `reality-classical`, or only a targeted lab test of `hello-stall` against both profiles?** *Recommended: the full row*, because the classical profile meets every censor the default does.
5. **A per-link WireGuard preshared key as a follow-up?** It restores post-quantum protection of the inner layer whatever the outer hello (`udp` links and X25519-picking targets too). Cost: a fresh key per link in both ends' maps; rotation is a flag day per link (one key per peer: the handshake fails until both ends have the new one); rollout needs the same capability gating. *Recommended: yes, its own note and ticket, built before or with `chrome-classical`*, so no link trades post-quantum protection for passing a stall.
