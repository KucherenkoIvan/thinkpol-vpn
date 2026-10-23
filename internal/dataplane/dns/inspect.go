package dns

// HostReport is what the host resolves names with, as it reports it, for
// diagnostics (`thinkpol diag`): read by Inspect, which changes nothing.
// Each source the OS keeps resolvers in is a part of its own.
type HostReport struct {
	// Unreadable says why no source was read.
	Unreadable string
	Sources    []HostSource
}

// HostSource is one place the OS keeps resolvers: "resolv.conf" and
// "systemd-resolved" on Linux, "scutil --dns" on macOS.
type HostSource struct {
	Name string
	// Unreadable says why the source couldn't be read; the rest is then
	// empty.
	Unreadable string
	// Present: the source is there (systemd-resolved runs). Without it
	// there is nothing to list.
	Present   bool
	Resolvers []HostResolver
}

// HostResolver is one resolver configuration the OS holds.
type HostResolver struct {
	// Interface is the link it is for (a systemd-resolved link, scutil's
	// if_index); "" for a global one.
	Interface string
	// Scoped: scutil lists it for queries scoped to Interface only.
	Scoped  bool
	Servers []string
	// Domains are the names it is asked for: systemd-resolved's domains
	// ("~" before a routing-only one; "~." takes every name), scutil's
	// match domain.
	Domains []string
	// Search are the search domains.
	Search []string
	// Order, Flags and Reach are scutil's; Options resolv.conf's or
	// scutil's.
	Order   int
	Flags   string
	Reach   string
	Options []string
	// NodeWritten: the node's own rewrite of resolv.conf (it keeps the
	// original in comments).
	NodeWritten bool
}

// resolvConfReport reads a resolv.conf's content.
func resolvConfReport(content []byte) HostResolver {
	r := HostResolver{NodeWritten: parseResolvConf(content).managed}
	for _, a := range nameservers(content) {
		r.Servers = append(r.Servers, a.String())
	}
	for _, f := range directives(content) {
		switch f[0] {
		case "search", "domain":
			r.Search = append(r.Search, f[1:]...)
		case "options":
			r.Options = append(r.Options, f[1:]...)
		}
	}
	return r
}
