package netcfg

// Inspect reads the owners' routes from the routing table. macOS has no
// policy rules: that list is always empty.
func Inspect() Inspection {
	return Inspection{RoutesUnreadable: "not read on macOS yet"}
}
