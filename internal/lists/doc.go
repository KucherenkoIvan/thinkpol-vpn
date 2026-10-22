// Package lists is the GeoIP list format: importers (v2fly geoip.dat, DB-IP
// Lite country CSV), CIDR aggregation and the content-addressed blob the map
// references (DESIGN.md "Lists"). Built offline by `thinkpol dev lists
// build` (later by the controller), distributed by dataplane/blobs, read by
// the rules (dataplane/rules), whose compiled table the router enforces. Pure Go, buildable for Android.
//
// # Sources
//
// Lists are built from files the operator downloads, either v2fly's
// geoip.dat or DB-IP's "IP to Country Lite" CSV (CC BY 4.0); the build
// prints the attribution the source asks for ([Format.Attribution]). Nothing
// here touches the network, no third-party data lives in the repository,
// and nodes never fetch lists from outside the network: they get them from
// their peers (dataplane/blobs). v2fly's geosite lists (names, not
// addresses) have a blob kind in the map but no importer yet.
//
// # Blobs
//
// One blob holds one list (a country, or a v2fly name such as "private") as
// its minimal set of IPv4 and IPv6 prefixes. Its encoding (see [Set.Blob])
// is canonical: the same addresses always give the same bytes, so the
// SHA-256 in the map's BlobRef is stable for the same input whatever the
// source, and however it was ordered, overlapped or split. The map names
// the blob with the list's name and kind geoip; rules say `geoip:<name>`.
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
//	built in:  Local (the local ranges), All (every address)
//
// # Built-in sets
//
// [Local] is what routing rules call `local`, fixed in code rather than
// downloaded: destinations on the physical network, which can't usefully go
// through an exit and hide nothing from a censor when they don't. It holds
// the LANs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7),
// link-local (169.254.0.0/16, fe80::/10), multicast (224.0.0.0/4,
// ff00::/8) and the limited broadcast 255.255.255.255. It never holds
// 100.64.0.0/10, the overlay's range: the space's own networks are decided
// before any rule, and other CGNAT addresses aren't a LAN. Loopback (the OS
// handles it before any route) and reserved ranges are out too. [All] is
// every address a list can hold: all of IPv4, and all of IPv6 but
// ::ffff:0:0/96.
package lists
