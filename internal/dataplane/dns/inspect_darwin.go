package dns

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Inspect reads the resolvers the OS uses as `scutil --dns` lists them:
// configd's resolver configuration, the node's own resolver, the
// services' (overridden or not) and other software's (another VPN's,
// /etc/resolver files) included. scutil only prints it.
func Inspect(ctx context.Context) HostReport {
	return inspectWith(ctx, scutil{path: scutilPath})
}

func inspectWith(ctx context.Context, s scutil) HostReport {
	src := HostSource{Name: "scutil --dns"}
	// The C locale: the listing parsed below is its.
	out, err := s.exec(ctx, "", []string{"LC_ALL=C"}, "--dns")
	if err != nil {
		src.Unreadable = "scutil --dns: " + err.Error()
		return HostReport{Sources: []HostSource{src}}
	}
	resolvers, err := parseScutilDNS([]byte(out))
	if err != nil {
		src.Unreadable = err.Error()
		return HostReport{Sources: []HostSource{src}}
	}
	src.Present, src.Resolvers = true, resolvers
	return HostReport{Sources: []HostSource{src}}
}

// scutilDNSHeader starts a section of `scutil --dns`: "DNS configuration",
// and "DNS configuration (for scoped queries)" for the resolvers only
// queries scoped to their interface use.
var scutilDNSHeader = regexp.MustCompile(`^DNS configuration( \(for scoped queries\))?$`)

// scutilResolver starts a resolver: "resolver #3".
var scutilResolver = regexp.MustCompile(`^resolver #[0-9]+$`)

// scutilEntry is a resolver's line: "nameserver[0] : 192.0.2.1",
// "flags    : Request A records".
var scutilEntry = regexp.MustCompile(`^([a-z_]+(?: [a-z_]+)*)(?:\[[0-9]+\])?\s*:\s*(.*)$`)

// scutilIndex is if_index's value: "15 (en0)".
var scutilIndex = regexp.MustCompile(`^[0-9]+ \((.+)\)$`)

// parseScutilDNS reads `scutil --dns`. A line it can't place (outside a
// section or a resolver, not "key : value") makes the listing unreadable,
// naming the line: a resolver read in part could hide where names go.
func parseScutilDNS(b []byte) ([]HostResolver, error) {
	var out []HostResolver
	section, scoped := false, false
	var cur *HostResolver
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for i, raw := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(raw)
		bad := func(why string) error {
			return fmt.Errorf("scutil --dns: line %d: %s: %q", i+1, why, l)
		}
		switch {
		case l == "" || l == "No DNS configuration available":
			continue
		case scutilDNSHeader.MatchString(l):
			flush()
			section, scoped = true, strings.Contains(l, "scoped")
			continue
		case scutilResolver.MatchString(l):
			if !section {
				return nil, bad("a resolver before any section")
			}
			flush()
			cur = &HostResolver{Scoped: scoped}
			continue
		}
		m := scutilEntry.FindStringSubmatch(l)
		switch {
		case m == nil:
			return nil, bad("not a resolver's entry")
		case cur == nil:
			return nil, bad("an entry outside a resolver")
		}
		if why := cur.setScutil(m[1], strings.TrimSpace(m[2])); why != "" {
			return nil, bad(why)
		}
	}
	flush()
	return out, nil
}

// setScutil sets what a `scutil --dns` entry says of r; other keys
// (timeout, port, ...) say nothing the snapshot keeps. It returns why the
// value can't be read, or "".
func (r *HostResolver) setScutil(key, value string) string {
	switch key {
	case "nameserver":
		r.Servers = append(r.Servers, value)
	case "search domain":
		r.Search = append(r.Search, value)
	case "domain":
		r.Domains = append(r.Domains, value)
	case "if_index":
		m := scutilIndex.FindStringSubmatch(value)
		if m == nil {
			return "an if_index without its interface"
		}
		r.Interface = m[1]
	case "flags":
		r.Flags = value
	case "reach":
		r.Reach = value
	case "order":
		n, err := strconv.Atoi(value)
		if err != nil {
			return "an order that isn't a number"
		}
		r.Order = n
	case "options":
		r.Options = append(r.Options, strings.Fields(value)...)
	}
	return ""
}
