package devmap

import (
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Chain is a chain of the spec: at M1, a name for an exit node.
type Chain struct {
	Name string
	// Exit is the exit node, an index into Spec.Nodes.
	Exit int
	Pos  Pos
}

type rawChain struct {
	pos  Pos
	Name scalar `yaml:"name"`
	Exit scalar `yaml:"exit"`
}

func (r *rawChain) UnmarshalYAML(node ast.Node) error {
	type fields rawChain // without this method
	var f fields
	if err := yaml.NodeToValue(node, &f, yaml.Strict()); err != nil {
		return err
	}
	*r = rawChain(f)
	r.pos = posOf(node)
	return nil
}

type rawPresets struct {
	Chain scalar `yaml:"chain"`
}

// routing checks the spec's chains, rules and presets; the map's builder
// checks the rest (the last rule is default, an exit is a peer of every
// device and allows egress).
func (c *checker) routing(s *Spec, raw *rawSpec, byName map[string]int) {
	chains := map[string]bool{}
	for _, rc := range raw.Chains {
		ch := Chain{Pos: rc.pos, Exit: -1}
		name, ok := c.value(rc.Name)
		switch {
		case !rc.Name.set():
			c.errorf(rc.pos, "chain without a name")
			ok = false
		case !ok:
		case netmap.CheckChainName(name) != nil:
			c.errorf(rc.Name.pos, "%v", netmap.CheckChainName(name))
			ok = false
		case chains[name]:
			c.errorf(rc.Name.pos, "chain %q is declared twice", name)
			ok = false
		}
		exit, exitOK := c.value(rc.Exit)
		i, known := byName[exit]
		switch {
		case !rc.Exit.set():
			c.errorf(rc.pos, "chain %s: exit is missing (a server's name)", name)
		case !exitOK:
		case !known:
			c.errorf(rc.Exit.pos, "chain %s: unknown node %q", name, exit)
		case s.Nodes[i].Kind != netmap.NodeServer:
			c.errorf(rc.Exit.pos, "chain %s: exit %s is not a server", name, exit)
		default:
			ch.Exit = i
		}
		if ok {
			chains[name] = true
			if ch.Exit >= 0 {
				ch.Name = name
				s.Chains = append(s.Chains, ch)
			}
		}
	}
	for _, rr := range raw.Rules {
		text, ok := c.value(rr)
		if !ok {
			continue
		}
		r, err := netmap.ParseRule(text)
		if err == nil {
			err = r.Check()
		}
		if err != nil {
			c.errorf(rr.pos, "%v", err)
			continue
		}
		if r.Action.Kind == netmap.ActionChain && !chains[r.Action.Chain] {
			c.errorf(rr.pos, "rule %s: unknown chain %q (declare it under chains)", r, r.Action.Chain)
			continue
		}
		s.Rules = append(s.Rules, r)
	}
	if v := raw.Presets.Chain; v.set() {
		if name, ok := c.value(v); ok {
			if !chains[name] {
				c.errorf(v.pos, "presets: unknown chain %q", name)
			} else {
				s.Presets.Chain = name
			}
		}
	}
}

// deviceRouting is what a device's section holds of the spec's routing.
func deviceRouting(s *Spec, ids []netmap.NodeID, sec *netmap.Section) {
	sec.Rules = append([]netmap.Rule(nil), s.Rules...)
	sec.Presets = s.Presets
	for _, ch := range s.Chains {
		sec.Chains = append(sec.Chains, netmap.Chain{Name: ch.Name, Exit: ids[ch.Exit]})
	}
}
