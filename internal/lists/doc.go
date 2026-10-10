// Package lists is the GeoIP/geosite list format: importers (v2fly, DB-IP),
// CIDR aggregation and the content-addressed blob the map references. Built
// offline by `thinkpol dev lists build` (later by the controller),
// distributed by dataplane/blobs, read by the router. Pure Go, buildable for
// Android.
package lists
