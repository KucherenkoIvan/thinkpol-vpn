---
id: TP-016
title: "GeoIP lists"
milestone: M1
area: lists
repo: thinkpol-vpn
size: M
depends_on: [TP-003]
refs: [R9]
owner: agent-tp-016
branch: tp-016-geoip-lists
---

## Goal
Country prefix lists in a compact, content-addressed form the map can reference.

## Scope
- Importers for v2fly `geoip.dat` and DB-IP Lite CSV into normalized per-country prefix sets.
- CIDR aggregation (merge adjacent and overlapping prefixes) with size stats.
- Content-addressed blob format (sha256 of canonical bytes) referenced from the map header.
- `thinkpol dev lists build`.
- Code lives in `internal/lists` (outside `dataplane`, since the controller builds lists too); distribution is TP-017's `dataplane/blobs`.

## Acceptance
- [x] building the same input twice gives the same hash — `TestSameInputSameHash` (same v2fly fixture twice, reversed entry order, and the same addresses from a DB-IP CSV, plain and gzipped: one hash); `TestBlobDeterministic` (100 random lists of up to 300 prefixes: shuffled with duplicates, and re-added as ranges, give identical bytes); `TestDevListsBuild` (the command run twice writes identical blobs); `TestBlobGolden` pins the bytes. On real data: DB-IP Lite 2026-10 built twice → RU `cc9e2d3c…f85b` both times, and v2fly's current geoip.dat gives the same hash (see Notes)
- [x] aggregation stats for the RU list recorded in Notes (prefix count before/after) — see "RU stats" below; aggregation correctness: `TestAggregationExhaustive` (1,200 random lists checked at every address of four 1024-address universes, IPv4 and IPv6, incl. the top of both spaces; output canonical and idempotent), `TestLookupMatchesNaive` (50 lists × 200 prefixes over the whole space, every input prefix's edges and neighbours plus 2,000 random addresses vs a linear scan), `TestRangesBecomeMinimalPrefixes`, `TestMergesOverlappingAndAdjacent`, `FuzzDecode` (20 s, 3.0 M execs) and `FuzzImportV2fly` (20 s, 79 k execs): no failure, every accepted blob re-encodes to itself

## Notes
**Source and licensing.** No third-party data is committed; tests use tiny inline fixtures. `thinkpol dev lists build` reads a local file only and never downloads; nodes never fetch lists from outside the network (TP-017 moves blobs between peers).
- **Default: DB-IP "IP to Country Lite" CSV**, CC BY 4.0: free to redistribute (the blobs are a derived work that spaces pass around) with attribution "IP Geolocation by DB-IP" (https://db-ip.com). Monthly at `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz` (format `start,end,CC`, IPv4 and IPv6, `ZZ` = unassigned/reserved). `dev lists build` prints the attribution under its table (`lists.Format.Attribution()`); the admin panel shows provenance and attribution (TP-042 Notes).
- **Also supported: v2fly `geoip.dat`** (`https://github.com/v2fly/geoip/releases/latest/download/geoip.dat`, repo CC BY-SA 4.0; its inputs are GeoLite2 or DB-IP depending on the build). Useful for its extra names (`private`, …). The 2026-10 release's `ru`, `by` and `de` hash identically to DB-IP Lite's, so it is evidently built from DB-IP Lite; for other builds the operator checks the data license (GeoLite2 data comes under MaxMind's own EULA, not a CC license). MMDB is not read: the CSV carries the same data with no extra dependency.

**Producing a blob.** `thinkpol dev lists build [-format v2fly|dbip] [-only ru,by] [-out dir] <source>`; the format comes from the name (`*.dat`, `*.csv`, either `.gz`) unless `-format` says. Writes `<out>/<name>.geoip` per list (all lists without `-only`) and prints name, SHA-256, size, and per family entries in (prefixes, or DB-IP ranges) vs prefixes out. Names are lowercased and must match `[a-z0-9][a-z0-9-]{0,31}` (a list asked for that's missing → error; with `-only`, other entries are skipped unchecked). Under the table it prints the source's attribution ("IP Geolocation by DB-IP (CC BY 4.0): https://db-ip.com"; for v2fly, CC BY-SA 4.0 and a hint that upstream data may carry DB-IP or GeoLite2 terms); entries left out for overlapping `::ffff:0:0/96` are a warning on stderr. A full DB-IP build leaves out one: ZZ's `::`–`1fff:ffff:…`.

**Blob format** (`lists.Set.Blob`, pinned by `TestBlobGolden`): `"TPIP"`, version `0x01`, uvarint IPv4 count, the IPv4 prefixes, uvarint IPv6 count, the IPv6 prefixes; a prefix is its length byte plus the first ceil(bits/8) address bytes (host bits zero). Prefixes are the set's **unique minimal CIDR list**: ascending, disjoint, no two mergeable (no sibling halves), so the bytes depend only on the address set: not on source, order, overlap, or prefixes-vs-ranges. Not compressed (compressor output can change between Go versions; the hash must not); TP-017 may compress on the wire. `Decode` accepts only that encoding (ascending check while parsing to bound memory, then re-encode and compare), so any accepted blob re-encodes to itself. **IPv4 lives only in the IPv4 family:** no list holds IPv6 overlapping `::ffff:0:0/96`. `Builder` refuses it (`ErrMappedIPv6`), importers keep IPv6 notation as IPv6 (no unmapping), leave such entries out and count them (`Stats.Skipped`), and `Decode` rejects them, so no IPv6 entry (`::/0`, `::ffff:0:0/96`) can put all of IPv4 into a `direct` list. `Contains` looks a mapped address up as the IPv4 address it maps. `Decode` also bounds the prefix count by the bytes left (every prefix but a lone /0 takes two bytes or more) before allocating. Sizes: RU 116,186 bytes, BY 3,041, DE 294,723; all 254 v2fly lists 7.9 MB together.

**RU stats** (2026-10 sources):
| source | IPv4 in → out | IPv6 in → out | blob |
|---|---|---|---|
| DB-IP Lite CSV | 9,925 ranges → 12,895 prefixes | 5,870 ranges → 10,088 prefixes | 116,186 B, sha256 `cc9e2d3c2e23e6ab29857ad3cd6357e41cfb8b1a194674c2ec5560a2e819f85b` |
| v2fly geoip.dat | 12,895 prefixes → 12,895 | 10,088 → 10,088 | same bytes, same hash |

Both upstreams already merge adjacent same-country blocks, so aggregation removes nothing for RU; DB-IP's ranges grow into prefixes because ranges aren't CIDR-aligned. The v2fly counts were cross-checked with an independent protobuf parse (12,895 / 10,088). Sanity: the RU set contains 77.88.8.8, 5.255.255.5 and 2a02:6b8::feed:ff (Yandex), not 8.8.8.8 or 2001:4860:4860::8888. TP-018's route count for "RU direct" is therefore ~12.9k IPv4 + ~10.1k IPv6 routes.

**Performance.** `Contains` is a binary search over sorted ranges: ~31 ns on the real RU set, ~34 ns in `BenchmarkContains` (13k IPv4 + 10k IPv6 random prefixes); decoding the RU blob takes ~2.5 ms; building all 254 v2fly lists from geoip.dat takes ~0.25 s.

**API** (`internal/lists`, pure Go, stdlib + `protowire`; no netmap or kernel imports):
- `Builder` (zero value ready): `AddPrefix(netip.Prefix)`, `AddRange(first, last netip.Addr)`, `AddSet(*Set)` (union), `Build() (*Set, Stats)`; `ErrInvalidPrefix`, `ErrMappedIPv6`. `Stats{Added4, Added6, Prefixes4, Prefixes6, Addresses4, Skipped}`.
- `Set` (immutable, nil = empty): `Contains(netip.Addr)` (mapped addresses as IPv4, zones ignored), `Prefixes() []netip.Prefix` (minimal, IPv4 first, ascending), `Equal(*Set)`, `Minus(*Set) *Set` (difference), `Blob() []byte`; `Decode([]byte) (*Set, error)` with `ErrMalformedBlob`, `ErrUnsupportedBlob`.
- `Import(io.Reader, Format, only []string) (map[string]*Builder, error)` (`FormatV2flyGeoIP` = `"v2fly"`, `FormatDBIPCSV` = `"dbip"`, gzip detected by magic, at most 256 MiB after decompression and 4 Mi entries (CSV rows, v2fly CIDRs of kept lists; all of v2fly's geoip.dat is 1.38 M, DB-IP's CSV 711 k rows); a v2fly CIDR without a prefix length is /0 (proto3 default); v2fly `reverse_match` entries are refused when kept); `ErrUnknownName`; `Format.Attribution()`; `FormatFromPath`; `CheckName`; `BuildAll(map) []List{Name, Set, Blob, SHA256, Stats}`.

**For downstream tickets:**
- **TP-015 (rules):** `geoip:<name>` resolves to the section `BlobRef` with `Kind == netmap.BlobGeoIP` and that `Name`; the router gets the bytes from TP-017's store and `lists.Decode`s them (verify the SHA-256 first). First match wins via `Set.Minus`; local ranges come from a built-in fixed list, and which of them go direct in "all but domestic" (not `100.64.0.0/10`, the overlay range) is decided in TP-015's Notes.
- **TP-017 (blobs):** a blob is opaque bytes named by `sha256(bytes)` with the size from the `BlobRef`; check both before handing it on. `lists.Decode` is the extra check for `BlobGeoIP`. Sizes are up to a few hundred KB per country (DE ~295 KB), so no chunking is needed; compressing on the wire is fine, the hash is over the uncompressed bytes.
- **TP-018 (route table):** `Set.Prefixes()` is already the merged minimal CIDR list (adjacent and overlapping merged), IPv4 then IPv6, ascending. RU is ~23k routes in total. Any coarsening for Windows (TP-047) may only shrink the direct set, never grow it (growing sends foreign traffic in the clear); in TP-018's Notes.
- **TP-020 (DNS) / geosite:** `BlobKind` geosite is reserved in the map but there is no geosite importer or format here (domains are R8, later). A geosite blob would need its own magic (not `TPIP`) and canonical form (sorted, deduplicated, lowercased domain rules).
- **TP-004 / controller:** `netmap.BlobRef{Kind: netmap.BlobGeoIP, SHA256: l.SHA256, Size: uint64(len(l.Blob)), Name: l.Name}` from a `lists.List`; header refs unnamed. TP-004's `dev map` spec has no blob refs yet (`dev map inspect` prints them): whoever first needs a hand-made map with lists (TP-015/TP-017 lab tests) adds a spec field taking `.geoip` files.
- **TP-042 (admin panel):** shows list provenance and attribution; in its Notes.

## Review findings
No blockers; orchestrator decisions.

- [x] R1. `Decode` rejects IPv6 prefixes inside `::ffff:0:0/96` (bits > 96 there decoded as IPv6 while `Contains` looks mapped addresses up as IPv4); such a blob is a `FuzzDecode` seed and a `TestDecodeRejectsNonCanonical` case — `Decode` rejects any IPv6 prefix overlapping the range (`::ffff:1.2.0.0/112`, `::/0`, `::/64`) in `TestDecodeRejectsNonCanonical`; the first is a `FuzzDecode` seed, and the fuzz body fails on any accepted mapped prefix (20 s, 2.6 M execs)
- [x] R2. IPv4-mapped rule (a list must never swallow all of IPv4 into `direct`): importers keep IPv6-notation entries as IPv6 (no unmapping); `Builder` and importers reject any IPv6 entry overlapping `::ffff:0:0/96` with a clear error (the dev command may count and skip with a warning if a real source has one; the built set never contains it); `Contains` on a mapped address documented; the rule stated in the format doc — `ErrMappedIPv6` from `AddPrefix`/`AddRange` (`TestRejectsInvalidInput`: `::/0`, `::/64`, `::/80`, `::ffff:0:0/96`, `::fffe:0:0/95`, mapped /97–/128, ranges across the edges); `TestImportLeavesOutMappedIPv6` (v2fly `::ffff:192.168.0.0/112` and DB-IP ZZ `::`–`1fff:…` left out, counted, no IPv4 leaks); `TestContainsEdges` (IPv6 everywhere but the mapped range never answers a mapped address); `TestRangesBecomeMinimalPrefixes` runs up to both edges; rule in `doc.go`, `blob.go`, `ErrMappedIPv6` and `Contains` docs; CLI warning tested in `TestDevListsBuild`
- [x] R3. v2fly importer: a missing field 2 is prefix length 0 (proto3 default); test fixed — `TestV2flyMissingPrefixIsZero`
- [x] R4. Attribution: `dev lists build` prints "IP Geolocation by DB-IP (CC BY 4.0)" for dbip and a license hint for v2fly (CC BY-SA 4.0; upstream may carry GeoLite2 terms), and its summary says so; TP-042 Notes: the admin panel shows list provenance and attribution — `TestAttribution`, `TestDevListsBuild` (attribution line under the table); summary "…; prints the source's attribution"; TP-042 Notes
- [x] R5. Import cap lowered to 256 MiB; row/entry counts capped — `maxSourceSize` 256 MiB, `maxEntries` 4 Mi (`TestImportStopsAtSizeCap`, `TestImportStopsAtEntryCap`); real sources fit with room (v2fly 1.38 M entries, DB-IP 711 k rows)
- [x] R6. Handoffs copied into downstream Notes: TP-015 (set difference, added in `internal/lists` if small; the built-in LAN/private list and which ranges go direct in "all but domestic"), TP-018 (~23k RU prefixes; coarsening for Windows may only shrink the direct set) — `Set.Minus` added (`TestMinus`: 1,200 random pairs checked at every address of four universes, result canonical); TP-015 Notes (difference, built-in local list, what goes direct), TP-018 Notes (route count, shrink-only coarsening)
- [x] N1. Tighter preallocation in `Decode` — count bounded by bytes left / 2 + 1, then preallocated exactly

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-016, branch: tp-016-geoip-lists
- 2026-10-10 docs: DESIGN "Lists" says what a GeoIP blob is (canonical minimal prefix set), that sources are operator-downloaded files (DB-IP Lite by default) and that no third-party data is in the repo
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 6 findings and a nit from review, none blocking
- 2026-10-10 has-errors → in-progress — owner: agent-tp-016, branch: tp-016-geoip-lists
- 2026-10-10 review fixes: IPv4-mapped rule, proto3 prefix default, attribution, 256 MiB / 4 Mi entry caps, `Set.Minus`, tighter `Decode` bound; handoffs in TP-015, TP-018 and TP-042 Notes; merged `rewrite` (TP-004, TP-007), `dev lists build` summary now starts "development tooling:"
- 2026-10-10 in-progress → review — every review finding checked; `make lint` and `make test` pass
- 2026-10-10 review → done — merged into rewrite
