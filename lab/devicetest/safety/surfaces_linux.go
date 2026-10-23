package safety

// surfaces are what the core records of a Linux host: only the lab uses
// it, to test the core as root, so only the IPv4 main table (a fresh
// node's IPv6 link-local routes still come and go while it settles).
func surfaces() []surface {
	return []surface{{name: "routes", argv: []string{ipPath(), "-4", "route", "show", "table", "main"}, norm: outputLines, next: "delete the route by hand"}}
}
