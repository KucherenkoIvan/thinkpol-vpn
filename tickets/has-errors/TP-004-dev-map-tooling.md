---
id: TP-004
title: "Dev tooling for hand-made maps"
milestone: M0
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-003]
refs: [DESIGN#joining]
owner: agent-tp-004
branch: tp-004-dev-map-tooling
---

## Goal
Until the controller exists (M4), maps made by hand from a YAML spec drive the lab and early real use.

## Scope
- `thinkpol dev keygen`: space signing and recovery keys, node keys; private key files written `0600`.
- `thinkpol dev map build spec.yaml --out map.bin`: assigns overlay IPv4 from `100.64.0.0/10` and IPv6 from a random ULA /48 unless fixed in the spec, builds and seals each node's section, pads, signs.
- `thinkpol dev map inspect map.bin [--node-key k]`: verifies and prints the header; with a node key, prints that node's section.
- Spec format documented (in `lab/README.md` or command help) with an example used by the lab.

## Out of scope
The admin CLI and controller (TP-034 decides whether these commands stay).

## Acceptance
- [x] the lab generates its maps with these commands — `lab/maps/m0.yaml` is the lab's M0 map (device-a, device-b, server-1 as relay, udp over IPv4 and IPv6), and its header gives the command sequence; `TestDevMapLabWorkflow` runs exactly that sequence through the CLI (`dev keygen space`, `dev keygen node`, `dev map build` with `SERVER_1_IPV4`/`SERVER_1_IPV6` from the environment, `dev map inspect` with each node's key) and checks every node's section. The lab harness (TP-002) isn't merged yet, so calling these from a lab test is TP-012's (see Notes)
- [x] `inspect` reports a tampered map as invalid — `TestDevMapInspectRejectsTamperedMaps`: a flipped header byte, sealed-section byte, signature byte and a truncated map each exit 1 with "… is not a valid map of space …" and print nothing; `TestDevMapLabWorkflow`: the map checked against another space's `space.pub` is invalid, a key with no section gets "no section for this node key"
- [x] the commands are clearly labelled as development tooling — they live under `dev`, every summary starts with "development tooling:" (`TestDevCommandsAreLabelledAsDevelopmentTooling`), key files start with "# thinkpol development keys.", the package is documented as such and DESIGN.md's layout lists `internal/devmap` as development tooling until the controller

## Notes
**Commands** (Go flag syntax, flags before arguments, as everywhere in the CLI: `dev map build -out map.bin spec.yaml`, not the Scope's `spec.yaml --out map.bin`):
- `thinkpol dev keygen space [-out keys]` writes `space.key` (space id and signing key, 0600), `recovery.key` (0600, keep offline) and `space.pub` (space id, signing and recovery public keys: the trust anchor every node gets).
- `thinkpol dev keygen node [-out keys] <name>...` writes `<name>.key` (map and WireGuard private keys, 0600, for that node only) and `<name>.pub` (public halves, all the builder reads). All names are checked before anything is written; no key file is ever replaced (O_EXCL).
- `thinkpol dev map build [-keys keys] [-out map.bin] [-version n] <spec.yaml>`: version defaults to the current Unix time, so a rebuild is newer; the map is written atomically (temp file + rename).
- `thinkpol dev map inspect [-keys keys] [-node-key file] <map.bin>`: verifies against `keys/space.pub` (exit 1 if invalid), prints the header, and with a node key that node's section; node ids are named from the `*.pub` files in `-keys`. Credentials print as length + SHA-256 prefix, never in full.
- `thinkpol dev map spec`: prints the annotated reference spec (`internal/devmap/reference.yaml`, embedded), which is the format documentation from command help. Added beyond Scope because the registry has no long help.

**Spec format: YAML**, because it is readable, takes comments (the examples explain themselves), and nests lists of paths naturally; JSON has no comments and TOML is awkward for lists of lists. Parsed with `github.com/goccy/go-yaml` v1.19.2: already in the module graph through go-kernel, maintained (unlike the archived `gopkg.in/yaml.v3`), pure Go, strict decoding (unknown fields are errors) and typed errors with positions. Every value carries its line and column (a `NodeUnmarshaler`), so every error, ours or the parser's, reads `file:line:col: message`; all problems are reported at once (up to 20). Values quoted when YAML could misread them (goccy misreads `udp://…` inside a flow mapping inside a flow list; block style or quotes work).
```yaml
space: {ipv4: 100.64.0.0/10, ipv6: fd12:3456:789a::/48}   # both optional
nodes:
  - name: server-1            # [a-z0-9][a-z0-9-]*, not space/recovery; names the key files
    kind: server              # server | device
    ipv4: 100.64.0.1          # optional; ipv6 too (needs space.ipv6)
    endpoints: [udp://192.0.2.1:4500, "udp://[2001:db8::1]:4500"]   # IP literals only
    listen: [udp://0.0.0.0:4500]                                  # optional
  - {name: device-a, kind: device}
paths:
  - [device-a, server-1]               # ends are peers; the nodes between relay
  - [device-a, server-1, device-b]
```
`${NAME}` in any value is filled from the environment (unset or empty is an error at its location): the lab's addresses are Docker's, known only once it is up.

**Derivation** (simple and documented in `internal/devmap/doc.go` and the reference spec):
- Path ends are WireGuard peers; each gets its neighbour on the path as a candidate first hop. Several paths between the same ends add first hops in written order (failover order). Nodes inside a path must be servers and route to both ends via their neighbours (next hops merge in path order).
- Neighbours on paths are linked once: the node without endpoints dials the one with; if both have endpoints, the one listed first dials; neither is an error. The dialer's `Link` lists all the dialed node's endpoints; the dialed node gets one `InboundLink` per transport with the dialer's kind.
- One random 32-byte secret per link and transport (udp `MinSecretSize`), fresh on every build: the dialer's credential and the listener's verifier (udp is symmetric). Every generated entry is run through the transport's `CheckEndpoint`/`CheckInbound`, as the engine will. Transport settings are empty (udp's settings messages are empty); a transport with settings needs spec fields first. Only `udp` is accepted.
- Listeners, unless written: one per (transport, port, family) of the endpoints, on `0.0.0.0` / `[::]`.
- Overlay addresses: the lowest free host address in spec order, around fixed ones. IPv6 /48: the spec's, else `fd` + 40 bits of SHA-256 of the space id: random per space as RFC 4193 wants, but stable across builds (the Scope's "random ULA /48" taken per space, not per build, so rebuilding doesn't renumber nodes).
- Node ids: first 8 bytes of SHA-256("thinkpol-vpn dev node id", space id, map public key): stable across builds while keys are, unlinkable without the public map key (never in a map), different per space.
- Validation: names, kinds, networks (IPv4 inside 100.64.0.0/10 and masked, IPv6 a masked /48 in fd00::/8), fixed addresses (inside, not the network address, unique), endpoints (`transport://ip:port`, known transport, IP literal, no zone, no IPv4-mapped, port ≠ 0, not unspecified, no duplicates), listeners cover endpoint transports, paths (≥ 2 nodes, known, no repeats, only servers inside, no duplicate or reversed duplicate path, someone can dial each pair). Missing key files are reported at the node's spec position. `netmap.Build`'s own policy is the backstop.

**Tests:** `internal/devmap/testdata/{reference,m0}.golden` are the full inspect output (header, then each node's opened section) of the reference spec (4 nodes: failover paths, a two-relay path, a server-server link, IPv4-only and dual-stack servers) and the lab spec, with deterministic keys and secrets (`go test ./internal/devmap -run TestGolden -update` rewrites them; review a diff as a change in what nodes know). `TestSectionsHoldOnlyWhatTheirNodeNeeds` checks independently of the goldens that each section names exactly its path peers, neighbours and relayed destinations, and that each link secret is in exactly its two ends' sections. Also: 39 spec-error cases with exact positions, variables, listener derivation, who dials, address assignment and exhaustion, stable default /48, rebuild keeps ids and addresses but not secrets (and `netmap.Accept` takes the rebuild), key files (round trip, 0600/0644, never replaced, partial space refused, path-like names refused, hex YAML would read as a number, low-order keys).

**For TP-011 (`thinkpol up`):** a node needs three files: its `<name>.key` (`devmap.ReadNodeKey` → `NodeKey{Map netmap.NodePrivateKey, WireGuard WireGuardPrivateKey}`, WireGuard key clamped, hex), `space.pub` (`devmap.ReadTrust` → `netmap.Trust`) and the map (`netmap.Verify(env, trust)`, then `(*Map).Open(key.Map)`). The node's own id is `Section.Node.ID`. Files are `field: "hex"` YAML with a comment line; TP-011 may move the node key file format into the agent when it defines the state dir.

**For TP-012 (M0 in the lab):** use `lab/maps/m0.yaml` as is. After `lab.Start`, run the header's sequence (on the host with `go run ./cmd/thinkpol`, or in a node, where `thinkpol` is on PATH and the checkout is at `/src`), with `SERVER_1_IPV4`/`SERVER_1_IPV6` = server-1's addresses on the servers network, then give each node `map.bin`, `space.pub` and only its own `<name>.key`. All nodes must get the same build (secrets are fresh per build). Overlay addresses: server-1 is 100.64.0.1, device-a .2, device-b .3, and `::1/2/3` in the space's derived /48 (read it from `dev map inspect`).

**Gotcha for TP-008/TP-010/TP-011 (whoever opens listeners):** the derived listeners for a dual-stack server are `udp 0.0.0.0:4500` and `udp [::]:4500`, as the map defines them ("every address of its family"). `udp.Listen` uses network `"udp"`, and Go turns a wildcard listen on `"udp"` into one dual-stack IPv6 socket even for `0.0.0.0`, so opening both would fail with "address in use". Listen with `udp4`/`udp6` by the address's family (or bind once); until then a spec can write `listen: [udp://[::]:4500]`.

**For TP-013:** ingress/egress settings need spec fields (`ingress: true`, …) and a rule that devices only link to ingress nodes (and never get an ingress-off node's endpoints). **For TP-034:** whether `dev keygen`/`dev map` stay; `internal/devmap` imports only `netmap` and the transport adapters.

## Review findings
Two reviewers; decisions by the orchestrator.

Blockers:
- [ ] B1 ULA: a truly random ULA /48 generated by `dev keygen space` and stored in space.key; Plan uses it unless the spec sets one. Node ids keyed (HMAC with the signing seed over space id + node public key) or random and stored, so netmap's "random and opaque" stays true
- [ ] B2 Runtime keys: `WireGuardPrivateKey` (+ `ParseWireGuardPrivateKey`, redacted `String`/`GoString`) moves into `internal/netmap` next to `NodePrivateKey`. devmap stays dev-only: depguard rule "devmap only importable from cmd/thinkpol". TP-011's Notes: `thinkpol up` defines its own state-dir/key-file format in `internal/agent` (may reuse the on-disk layout, reader outside devmap)

Should-fix:
- [ ] S1 Version: `NextVersion` (now, or one past the existing output map's version); reject `-version` > `netmap.MaxVersion` with a clear message; `Keys.Trust()`
- [ ] S2 Reject forwarding loops in derived routes (cycle check per destination), with the two-path loop test
- [ ] S3 Keygen all-or-nothing (roll back written files; pre-check all names incl. duplicates); validation out of the cmd file
- [ ] S4 Devices can't have endpoints or listen
- [ ] S5 udp adapter listens with udp4/udp6 by address family (`internal/dataplane/transport/udp`), with a test binding 0.0.0.0:p and [::]:p at once; recorded here only
- [ ] S6 A real 3+ hop path in reference.yaml and the goldens; fix the ticket's claim
- [ ] S7 Test: no private key hex in stdout/stderr of any command
- [ ] S8 The key loader refuses modes looser than 0600 (non-Windows)

Nits:
- [ ] netmap parsers with positions; redacted `String` on `SpaceKeys`/`Keys`; listener family check at the listen entry; no double error on an unset variable; Links derivation moves into Plan; fsync files (and dir) on write; umask-independent permission tests; `-recovery-out` flag or an explicit instruction to move recovery.key offline

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-004, branch: tp-004-dev-map-tooling
- 2026-10-10 docs: DESIGN.md repository layout lists `internal/devmap` (development tooling until the controller)
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 2 blockers, 8 should-fix, nits (see Review findings)
