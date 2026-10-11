package devmap

import (
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Reference is the spec format, annotated: a spec using every field.
//
//go:embed reference.yaml
var Reference string

// Spec is a validated spec: a space's nodes and the paths between them,
// with the links those paths need (see the package doc for the format).
type Spec struct {
	File string
	// IPv4Network is the overlay IPv4 network (100.64.0.0/10 unless the spec
	// narrows it). IPv6Network is the ULA /48, invalid when the spec leaves it
	// to Plan, which derives it from the space id.
	IPv4Network netip.Prefix
	IPv6Network netip.Prefix
	Nodes       []Node
	Paths       []Path
	// Lists are the space's GeoIP lists: every one goes into the map's
	// header, and into the sections of the nodes that name it. ReadLists
	// reads their files.
	Lists []List
}

// List is a GeoIP list blob, as `thinkpol dev lists build` writes it.
type List struct {
	Name string
	// File is where the blob is: relative to the spec's directory unless
	// absolute.
	File string
	Pos  Pos
	// Ref is the blob's reference, named, once ReadLists read it.
	Ref netmap.BlobRef
}

// Node is one node of the spec.
type Node struct {
	Name string
	Kind netmap.NodeKind
	// IPv4 and IPv6 are the overlay addresses fixed in the spec; invalid
	// when Plan assigns them.
	IPv4, IPv6 netip.Addr
	// Endpoints are the addresses other nodes dial to reach this one.
	Endpoints []Address
	// Listeners are as written, or derived from Endpoints.
	Listeners []Address
	// Lists are the lists the node uses, indexes into Spec.Lists: its
	// section names them.
	Lists []int
	Pos   Pos
}

// Address is a transport and an IP literal with a port, written
// transport://ip:port.
type Address struct {
	Transport string
	AddrPort  netip.AddrPort
}

func (a Address) String() string { return a.Transport + "://" + a.AddrPort.String() }

// Path is a way between two nodes: its ends are WireGuard peers of each
// other, and the nodes in between relay.
type Path struct {
	// Nodes are indexes into Spec.Nodes, from one end to the other; Hops
	// are where each was written.
	Nodes []int
	Hops  []Pos
	Pos   Pos
}

// Pos is a 1-based line and column in a spec; zero when unknown.
type Pos struct{ Line, Col int }

// Error is a problem with a spec, at the place it was written.
type Error struct {
	File string
	Pos  Pos
	Msg  string
}

func (e *Error) Error() string {
	if e.Pos.Line == 0 {
		return e.File + ": " + e.Msg
	}
	return fmt.Sprintf("%s:%d:%d: %s", e.File, e.Pos.Line, e.Pos.Col, e.Msg)
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	ula       = netip.MustParsePrefix("fd00::/8")
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	varRefRE  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	reserved  = []string{"space", "recovery"} // key file names of the space
	maxErrors = 20
)

// CheckName reports whether name can name a node: it names the node's key
// files too, so it is kept to lowercase letters, digits and dashes.
func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("node name %q: use 1-63 lowercase letters, digits and dashes, starting with a letter or digit", name)
	}
	if slices.Contains(reserved, name) {
		return fmt.Errorf("node name %q is reserved for the space's key files", name)
	}
	return nil
}

// ParseSpec reads and validates a spec. ${NAME} in a value is replaced by
// lookup(NAME) (the environment, for the command), so a spec can take
// addresses known only at run time. The error lists every problem found,
// each as file:line:column: message.
func ParseSpec(file string, data []byte, lookup func(string) (string, bool)) (*Spec, error) {
	var raw rawSpec
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.Strict()); err != nil {
		return nil, decodeError(file, err)
	}
	c := checker{file: file, lookup: lookup}
	s := c.spec(&raw)
	if len(c.errs) > 0 {
		return nil, errors.Join(c.errs...)
	}
	return s, nil
}

func decodeError(file string, err error) error {
	var located *Error
	if errors.As(err, &located) {
		e := *located
		e.File = file
		return &e
	}
	var ye yaml.Error
	if errors.As(err, &ye) {
		e := &Error{File: file, Msg: ye.GetMessage()}
		if t := ye.GetToken(); t != nil && t.Position != nil {
			e.Pos = Pos{t.Position.Line, t.Position.Column}
		}
		return e
	}
	return &Error{File: file, Msg: err.Error()}
}

type rawSpec struct {
	Space struct {
		IPv4 scalar `yaml:"ipv4"`
		IPv6 scalar `yaml:"ipv6"`
	} `yaml:"space"`
	Lists []rawList `yaml:"lists"`
	Nodes []rawNode `yaml:"nodes"`
	Paths []rawPath `yaml:"paths"`
}

type rawList struct {
	pos  Pos
	Name scalar `yaml:"name"`
	File scalar `yaml:"file"`
}

func (l *rawList) UnmarshalYAML(node ast.Node) error {
	type fields rawList // without this method
	var f fields
	if err := yaml.NodeToValue(node, &f, yaml.Strict()); err != nil {
		return err
	}
	*l = rawList(f)
	l.pos = posOf(node)
	return nil
}

type rawNode struct {
	pos       Pos
	Name      scalar   `yaml:"name"`
	Kind      scalar   `yaml:"kind"`
	IPv4      scalar   `yaml:"ipv4"`
	IPv6      scalar   `yaml:"ipv6"`
	Endpoints []scalar `yaml:"endpoints"`
	Listen    []scalar `yaml:"listen"`
	Lists     []scalar `yaml:"lists"`
}

func (n *rawNode) UnmarshalYAML(node ast.Node) error {
	type fields rawNode // without this method
	var f fields
	if err := yaml.NodeToValue(node, &f, yaml.Strict()); err != nil {
		return err
	}
	*n = rawNode(f)
	n.pos = posOf(node)
	return nil
}

type rawPath struct {
	pos  Pos
	hops []scalar
}

func (p *rawPath) UnmarshalYAML(node ast.Node) error {
	p.pos = posOf(node)
	if _, ok := node.(*ast.SequenceNode); !ok {
		return &Error{Pos: p.pos, Msg: "a path is a list of node names, e.g. [device-a, server-1, device-b]"}
	}
	return yaml.NodeToValue(node, &p.hops, yaml.Strict())
}

// scalar is one value as written and where.
type scalar struct {
	text string
	pos  Pos
}

func (s *scalar) UnmarshalYAML(node ast.Node) error {
	s.pos = posOf(node)
	switch n := node.(type) {
	case *ast.NullNode:
		s.pos = Pos{} // as if absent
	case *ast.StringNode:
		s.text = n.Value
	case ast.ScalarNode:
		s.text = n.GetToken().Value
	default:
		return &Error{Pos: s.pos, Msg: fmt.Sprintf("expected a single value, found a %s", node.Type())}
	}
	return nil
}

func (s scalar) set() bool { return s.pos.Line != 0 }

func posOf(n ast.Node) Pos {
	// A mapping's own token is its first ':'; point at its first key instead.
	if m, ok := n.(*ast.MappingNode); ok && len(m.Values) > 0 {
		n = m.Values[0].Key
	}
	if t := n.GetToken(); t != nil && t.Position != nil {
		return Pos{t.Position.Line, t.Position.Column}
	}
	return Pos{}
}

type checker struct {
	file   string
	lookup func(string) (string, bool)
	errs   []error
}

func (c *checker) errorf(pos Pos, format string, args ...any) {
	if len(c.errs) == maxErrors {
		c.errs = append(c.errs, &Error{File: c.file, Msg: "too many errors"})
	}
	if len(c.errs) > maxErrors {
		return
	}
	c.errs = append(c.errs, &Error{File: c.file, Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

// value returns s with ${NAME} references replaced; ok is false (and the
// error recorded) when a reference can't be.
func (c *checker) value(s scalar) (string, bool) {
	ok := true
	text := varRefRE.ReplaceAllStringFunc(s.text, func(ref string) string {
		name := ref[2 : len(ref)-1]
		v, found := "", false
		if c.lookup != nil {
			v, found = c.lookup(name)
		}
		if !found || v == "" {
			c.errorf(s.pos, "%s is not set", ref)
			ok = false
		}
		return v
	})
	if ok && strings.Contains(text, "${") {
		c.errorf(s.pos, "malformed variable in %q: write ${NAME} with letters, digits and underscores", s.text)
		ok = false
	}
	return text, ok
}

func (c *checker) spec(raw *rawSpec) *Spec {
	s := &Spec{File: c.file, IPv4Network: cgnat}
	if v := raw.Space.IPv4; v.set() {
		if text, ok := c.value(v); ok {
			p, err := netip.ParsePrefix(text)
			switch {
			case err != nil || !p.Addr().Is4():
				c.errorf(v.pos, "space ipv4 %q is not an IPv4 network like 100.64.0.0/24", text)
			case p != p.Masked():
				c.errorf(v.pos, "space ipv4 %v is not a network address (%v is)", p, p.Masked())
			case !cgnat.Contains(p.Addr()) || p.Bits() < cgnat.Bits():
				c.errorf(v.pos, "space ipv4 %v is not inside %v", p, cgnat)
			default:
				s.IPv4Network = p
			}
		}
	}
	if v := raw.Space.IPv6; v.set() {
		if text, ok := c.value(v); ok {
			p, err := netip.ParsePrefix(text)
			switch {
			case err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Addr().Zone() != "":
				c.errorf(v.pos, "space ipv6 %q is not an IPv6 network like fd12:3456:789a::/48", text)
			case p != p.Masked():
				c.errorf(v.pos, "space ipv6 %v is not a network address (%v is)", p, p.Masked())
			case !ula.Contains(p.Addr()) || p.Bits() != 48:
				c.errorf(v.pos, "space ipv6 %v is not a /48 inside %v", p, ula)
			default:
				s.IPv6Network = p
			}
		}
	}

	listByName := c.lists(s, raw.Lists)
	if len(raw.Nodes) == 0 {
		c.errorf(Pos{}, "no nodes")
	}
	byName := map[string]int{}
	ipv4s, ipv6s := map[netip.Addr]string{}, map[netip.Addr]string{}
	for _, rn := range raw.Nodes {
		n := c.node(s, rn, ipv4s, ipv6s)
		n.Lists = c.nodeLists(n.Name, rn.Lists, listByName)
		if n.Name != "" {
			if _, dup := byName[n.Name]; dup {
				c.errorf(rn.Name.pos, "node %q is declared twice", n.Name)
			} else {
				byName[n.Name] = len(s.Nodes)
			}
		}
		s.Nodes = append(s.Nodes, n)
	}
	c.paths(s, raw.Paths, byName)
	return s
}

// lists checks the spec's lists and returns them by name.
func (c *checker) lists(s *Spec, raw []rawList) map[string]int {
	byName := map[string]int{}
	for _, rl := range raw {
		l := List{Pos: rl.pos}
		name, nameOK := c.value(rl.Name)
		switch {
		case !rl.Name.set():
			c.errorf(rl.pos, "list without a name")
			nameOK = false
		case !nameOK:
		case lists.CheckName(name) != nil:
			c.errorf(rl.Name.pos, "%v", lists.CheckName(name))
			nameOK = false
		}
		file, fileOK := c.value(rl.File)
		if !rl.File.set() || fileOK && file == "" {
			c.errorf(rl.pos, "list %s: file is missing (a blob `thinkpol dev lists build` wrote)", name)
			fileOK = false
		}
		if !nameOK || !fileOK {
			continue
		}
		if _, dup := byName[name]; dup {
			c.errorf(rl.Name.pos, "list %q is declared twice", name)
			continue
		}
		l.Name, l.File = name, file
		byName[name] = len(s.Lists)
		s.Lists = append(s.Lists, l)
	}
	return byName
}

// nodeLists resolves the lists a node names.
func (c *checker) nodeLists(label string, raw []scalar, byName map[string]int) []int {
	var out []int
	for _, v := range raw {
		name, ok := c.value(v)
		if !ok {
			continue
		}
		i, known := byName[name]
		switch {
		case !known:
			c.errorf(v.pos, "%s: unknown list %q (declare it under lists)", label, name)
		case slices.Contains(out, i):
			c.errorf(v.pos, "%s: list %q is named twice", label, name)
		default:
			out = append(out, i)
		}
	}
	return out
}

func (c *checker) node(s *Spec, rn rawNode, ipv4s, ipv6s map[netip.Addr]string) Node {
	n := Node{Pos: rn.pos}
	if !rn.Name.set() {
		c.errorf(rn.pos, "node without a name")
	} else if name, ok := c.value(rn.Name); ok {
		if err := CheckName(name); err != nil {
			c.errorf(rn.Name.pos, "%v", err)
		} else {
			n.Name = name
		}
	}
	label := n.Name
	if label == "" {
		label = "node"
		if rn.Name.text != "" {
			label = rn.Name.text
		}
	}

	switch kind, ok := c.value(rn.Kind); {
	case !rn.Kind.set():
		c.errorf(rn.pos, "%s: kind is missing (server or device)", label)
	case !ok:
	case kind == "server":
		n.Kind = netmap.NodeServer
	case kind == "device":
		n.Kind = netmap.NodeDevice
	default:
		c.errorf(rn.Kind.pos, "%s: kind %q is neither server nor device", label, kind)
	}

	if v := rn.IPv4; v.set() {
		if text, ok := c.value(v); ok {
			a, err := netip.ParseAddr(text)
			switch {
			case err != nil || !a.Is4():
				c.errorf(v.pos, "%s: ipv4 %q is not an IPv4 address", label, text)
			case !s.IPv4Network.Contains(a) || a == s.IPv4Network.Addr():
				c.errorf(v.pos, "%s: ipv4 %v is not a host address in %v", label, a, s.IPv4Network)
			case ipv4s[a] != "":
				c.errorf(v.pos, "%s: ipv4 %v is taken by %s", label, a, ipv4s[a])
			default:
				n.IPv4 = a
				ipv4s[a] = label
			}
		}
	}
	if v := rn.IPv6; v.set() {
		if text, ok := c.value(v); ok {
			a, err := netip.ParseAddr(text)
			switch {
			case err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "":
				c.errorf(v.pos, "%s: ipv6 %q is not an IPv6 address", label, text)
			case !s.IPv6Network.IsValid():
				c.errorf(v.pos, "%s: a fixed ipv6 needs the space's ipv6 network in the spec", label)
			case !s.IPv6Network.Contains(a) || a == s.IPv6Network.Addr():
				c.errorf(v.pos, "%s: ipv6 %v is not a host address in %v", label, a, s.IPv6Network)
			case ipv6s[a] != "":
				c.errorf(v.pos, "%s: ipv6 %v is taken by %s", label, a, ipv6s[a])
			default:
				n.IPv6 = a
				ipv6s[a] = label
			}
		}
	}

	if n.Kind == netmap.NodeDevice && (rn.Endpoints != nil || rn.Listen != nil) {
		at := rn.pos
		if len(rn.Endpoints) > 0 {
			at = rn.Endpoints[0].pos
		} else if len(rn.Listen) > 0 {
			at = rn.Listen[0].pos
		}
		c.errorf(at, "%s: a device has no endpoints or listeners: it dials servers", label)
		return n
	}
	n.Endpoints = c.addresses(label, "endpoint", rn.Endpoints, true)
	if rn.Listen == nil {
		n.Listeners = listenersFor(n.Endpoints)
		return n
	}
	n.Listeners = c.addresses(label, "listener", rn.Listen, false)
	at := rn.pos
	if len(rn.Listen) > 0 {
		at = rn.Listen[0].pos
	}
	for _, e := range n.Endpoints {
		if !slices.ContainsFunc(n.Listeners, func(l Address) bool { return l.Transport == e.Transport && is6(l) == is6(e) }) {
			c.errorf(at, "%s: endpoint %v has no %s listener of its address family", label, e, e.Transport)
		}
	}
	return n
}

func is6(a Address) bool { return a.AddrPort.Addr().Is6() }

// listenersFor derives a node's listeners from its endpoints: one per
// transport, port and address family, bound to every address of the family.
func listenersFor(endpoints []Address) []Address {
	var ls []Address
	for _, e := range endpoints {
		every := netip.IPv4Unspecified()
		if is6(e) {
			every = netip.IPv6Unspecified()
		}
		l := Address{e.Transport, netip.AddrPortFrom(every, e.AddrPort.Port())}
		if !slices.Contains(ls, l) {
			ls = append(ls, l)
		}
	}
	return ls
}

func (c *checker) addresses(label, what string, raw []scalar, dial bool) []Address {
	var out []Address
	for _, v := range raw {
		text, ok := c.value(v)
		if !ok {
			continue
		}
		a, err := parseAddress(text)
		switch {
		case err != nil:
			c.errorf(v.pos, "%s: %s %v", label, what, err)
		case dial && a.AddrPort.Addr().IsUnspecified():
			c.errorf(v.pos, "%s: endpoint %v has no address to dial (listen: binds every address)", label, a)
		case slices.Contains(out, a):
			c.errorf(v.pos, "%s: %s %v is listed twice", label, what, a)
		default:
			out = append(out, a)
		}
	}
	return out
}

func parseAddress(text string) (Address, error) {
	name, rest, ok := strings.Cut(text, "://")
	if !ok {
		return Address{}, fmt.Errorf("%q: write transport://ip:port, e.g. udp://192.0.2.1:4500 or udp://[2001:db8::1]:4500", text)
	}
	if _, ok := transports[name]; !ok {
		return Address{}, fmt.Errorf("%q: unknown transport %q (known: %s)", text, name, strings.Join(transportNames(), ", "))
	}
	ap, err := netip.ParseAddrPort(rest)
	switch {
	case err != nil:
		return Address{}, fmt.Errorf("%q: %q is not an IP literal with a port (no host names: nodes never resolve names)", text, rest)
	case ap.Addr().Zone() != "":
		return Address{}, fmt.Errorf("%q: no zones in map addresses", text)
	case ap.Addr().Is4In6():
		return Address{}, fmt.Errorf("%q: write an IPv4 address as IPv4, not IPv4-mapped IPv6", text)
	case ap.Port() == 0:
		return Address{}, fmt.Errorf("%q: port 0", text)
	}
	return Address{name, ap}, nil
}

func (c *checker) paths(s *Spec, raw []rawPath, byName map[string]int) {
	seen := map[string]Pos{}
	for _, rp := range raw {
		if len(rp.hops) < 2 {
			c.errorf(rp.pos, "a path needs at least two nodes, its two ends")
			continue
		}
		p := Path{Pos: rp.pos}
		ok := true
		for _, h := range rp.hops {
			name, valid := c.value(h)
			i, known := byName[name]
			switch {
			case !valid:
				ok = false
			case !known:
				c.errorf(h.pos, "unknown node %q", name)
				ok = false
			case slices.Contains(p.Nodes, i):
				c.errorf(h.pos, "%s appears twice in one path", name)
				ok = false
			default:
				p.Nodes = append(p.Nodes, i)
				p.Hops = append(p.Hops, h.pos)
			}
		}
		if !ok {
			continue
		}
		for k, i := range p.Nodes[1 : len(p.Nodes)-1] {
			if s.Nodes[i].Kind != netmap.NodeServer {
				c.errorf(rp.hops[k+1].pos, "%s is a device and can't relay: only servers sit inside a path", s.Nodes[i].Name)
				ok = false
			}
		}
		reversed := slices.Clone(p.Nodes)
		slices.Reverse(reversed)
		key, reverse := fmt.Sprint(p.Nodes), fmt.Sprint(reversed)
		if at, dup := seen[key]; dup {
			c.errorf(rp.pos, "same path as line %d", at.Line)
			ok = false
		} else if at, dup := seen[reverse]; dup {
			c.errorf(rp.pos, "same path as line %d, reversed", at.Line)
			ok = false
		}
		if !ok {
			continue
		}
		seen[key] = rp.pos
		s.Paths = append(s.Paths, p)
	}
}
