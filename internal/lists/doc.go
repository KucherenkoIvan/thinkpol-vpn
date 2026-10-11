// Package lists is the GeoIP list format: importers (v2fly geoip.dat, DB-IP
// Lite country CSV), CIDR aggregation and the content-addressed blob the map
// references. Built offline by `thinkpol dev lists build` (later by the
// controller), distributed by dataplane/blobs, read by the router. Pure Go,
// buildable for Android.
//
// One blob holds one list (a country, or a v2fly name such as "private") as
// an aggregated set of IPv4 and IPv6 addresses. Its encoding (see
// [Set.Blob]) is canonical: the same addresses always give the same bytes,
// so the SHA-256 in the map's BlobRef is stable for the same input however
// it was ordered, overlapped or split. The map names the blob with the
// list's name and kind geoip; rules say `geoip:<name>`.
//
// IPv4 lives only in the IPv4 family. No list holds IPv6 overlapping
// ::ffff:0:0/96, the IPv4-mapped addresses: builders refuse it
// ([ErrMappedIPv6]), importers leave it out and count it, [Decode] rejects
// it. So no IPv6 entry (::/0, ::ffff:0:0/96) can put all of IPv4 into a
// list, and [Set.Contains] looks a mapped address up as IPv4.
//
//	importers: Import(r, format, only) → map[name]*Builder
//	aggregate: Builder.Build() → *Set, Stats (prefix counts before/after)
//	encode:    Set.Blob() → bytes; sha256 of those names the blob
//	read:      Decode(blob) → *Set (canonical only); Set.Contains, Set.Prefixes
//	combine:   Builder.AddSet (union), Set.Minus (difference)
//	built in:  Local (LANs, link-local, multicast), All (every address)
//
// Nothing here touches the network: sources are files an operator fetched.
package lists
