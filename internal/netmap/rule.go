package netmap

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// Rule is one routing rule, `match → action` (docs/design/routing.md "Routing rules and
// DNS"). Rules are ordered and the first that matches a destination
// decides it. Its text form is `<match> -> <action>`, e.g.
// `geoip:ru -> direct`; see ParseRule.
type Rule struct {
	Match  Match
	Action Action
}

// MatchKind is what a rule matches destinations by.
type MatchKind uint8

const (
	MatchDefault      MatchKind = iota + 1 // every destination
	MatchLocal                             // the built-in local ranges (LANs, link-local, multicast)
	MatchCIDR                              // a prefix
	MatchGeoIP                             // a GeoIP list, by the name of the section's geoip blob
	MatchDomain                            // a domain name, exactly
	MatchDomainSuffix                      // a domain and every name under it
	MatchGeoSite                           // a geosite list, by the name of the section's geosite blob
)

var matchNames = [...]string{
	MatchDefault: "default", MatchLocal: "local", MatchCIDR: "cidr", MatchGeoIP: "geoip",
	MatchDomain: "domain", MatchDomainSuffix: "domain-suffix", MatchGeoSite: "geosite",
}

func (k MatchKind) known() bool { return k >= MatchDefault && k <= MatchGeoSite }

func (k MatchKind) String() string {
	if k.known() {
		return matchNames[k]
	}
	return "MatchKind(" + strconv.Itoa(int(k)) + ")"
}

// ByName reports whether the matcher matches domain names rather than
// addresses. Such rules are kept in the map but can't be enforced by
// routes: only in userspace mode (later) and by the DNS resolver.
func (k MatchKind) ByName() bool {
	return k == MatchDomain || k == MatchDomainSuffix || k == MatchGeoSite
}

// Match is a rule's matcher.
type Match struct {
	Kind MatchKind
	// Prefix is a cidr matcher's prefix.
	Prefix netip.Prefix
	// Value is a geoip or geosite matcher's list name, or a domain or
	// domain-suffix matcher's domain; for an unknown kind, its argument as
	// the map has it.
	Value string
}

func (m Match) String() string {
	switch m.Kind {
	case MatchDefault, MatchLocal:
		return m.Kind.String()
	case MatchCIDR:
		return "cidr:" + prefixString(m.Prefix)
	}
	return m.Kind.String() + ":" + m.Value
}

// ActionKind is what a rule does with the destinations it matches.
type ActionKind uint8

const (
	ActionDirect ActionKind = iota + 1 // around the tunnel, through the physical network
	ActionChain                        // through a chain
	ActionBlock                        // dropped
)

func (k ActionKind) known() bool { return k >= ActionDirect && k <= ActionBlock }

func (k ActionKind) String() string {
	switch k {
	case ActionDirect:
		return "direct"
	case ActionChain:
		return "chain"
	case ActionBlock:
		return "block"
	}
	return "ActionKind(" + strconv.Itoa(int(k)) + ")"
}

// Action is a rule's action. Comparable: equal actions send traffic the
// same way.
type Action struct {
	Kind ActionKind
	// Chain names the chain, for ActionChain.
	Chain string
}

var (
	Direct = Action{Kind: ActionDirect}
	Block  = Action{Kind: ActionBlock}
)

// ToChain is the action that sends traffic through the named chain.
func ToChain(name string) Action { return Action{Kind: ActionChain, Chain: name} }

func (a Action) String() string {
	if a.Kind == ActionChain {
		return "chain:" + a.Chain
	}
	return a.Kind.String()
}

func (r Rule) String() string { return r.Match.String() + " -> " + r.Action.String() }

// Chain is a named way out to the internet as a node sees it: its exit, a
// WireGuard peer reached through the peer's candidate first hops (relays
// route the rest of the way). At M1 a chain is a single exit node.
type Chain struct {
	Name string
	Exit NodeID
}

// RulePresets are what a device's rule presets are built from. "everything"
// sends all but the local ranges through Chain; "all but domestic" also
// keeps the GeoIP list Domestic out of the tunnel. Empty fields make the
// presets that need them unavailable.
type RulePresets struct {
	// Domestic names a geoip blob of the section, e.g. a country code.
	Domestic string
	Chain    string
}

const (
	maxListName = 32
	// Chain names share the list names' limit.
	maxChainName = maxListName
	maxDomain    = 253
)

// mappedRange is ::ffff:0:0/96: IPv4 is matched only as IPv4 (lists hold
// the same rule), so no IPv6 cidr may lie inside it, and one around it
// (::/0) matches all of IPv6 but it.
var mappedRange = netip.MustParsePrefix("::ffff:0:0/96")

// ParseRule reads a rule's text form, `<match> -> <action>` (or with
// `→`): matchers `default`, `local`, `cidr:<prefix>`, `geoip:<list>`,
// `domain:<name>`, `domain-suffix:<name>`, `geosite:<list>`; actions
// `direct`, `block`, `chain:<name>`. Domains are lowercased and lose a
// trailing dot. The result passes Check.
func ParseRule(s string) (Rule, error) {
	m, a, ok := strings.Cut(s, "->")
	if !ok {
		m, a, ok = strings.Cut(s, "→")
	}
	if !ok {
		return Rule{}, fmt.Errorf("rule %q: want <match> -> <action>", s)
	}
	match, err := ParseMatch(strings.TrimSpace(m))
	if err != nil {
		return Rule{}, err
	}
	action, err := ParseAction(strings.TrimSpace(a))
	if err != nil {
		return Rule{}, err
	}
	return Rule{Match: match, Action: action}, nil
}

// ParseMatch reads a matcher's text form (see ParseRule).
func ParseMatch(s string) (Match, error) {
	kind, arg, hasArg := strings.Cut(s, ":")
	var m Match
	for k := MatchDefault; k <= MatchGeoSite; k++ {
		if matchNames[k] == kind {
			m.Kind = k
		}
	}
	switch m.Kind {
	case 0:
		return Match{}, fmt.Errorf("matcher %q: unknown kind %q", s, kind)
	case MatchDefault, MatchLocal:
		if hasArg {
			return Match{}, fmt.Errorf("matcher %q: %s takes no argument", s, kind)
		}
	case MatchCIDR:
		p, err := netip.ParsePrefix(arg)
		if err != nil {
			return Match{}, fmt.Errorf("matcher %q: %v", s, err)
		}
		m.Prefix = p
	case MatchDomain, MatchDomainSuffix:
		m.Value = strings.TrimSuffix(strings.ToLower(arg), ".")
	default:
		m.Value = arg
	}
	if err := m.check(); err != nil {
		return Match{}, fmt.Errorf("matcher %q: %w", s, err)
	}
	return m, nil
}

// ParseAction reads an action's text form: `direct`, `block` or
// `chain:<name>`.
func ParseAction(s string) (Action, error) {
	var a Action
	switch kind, name, _ := strings.Cut(s, ":"); {
	case s == "direct":
		a = Direct
	case s == "block":
		a = Block
	case kind == "chain":
		a = ToChain(name)
	default:
		return Action{}, fmt.Errorf("action %q: want direct, block or chain:<name>", s)
	}
	if err := a.check(); err != nil {
		return Action{}, fmt.Errorf("action %q: %w", s, err)
	}
	return a, nil
}

// Check is the builder's rule for a rule: a known matcher with a valid
// argument and a known action. Readers don't apply it: a node keeps a rule
// it can't enforce and reports it.
func (r Rule) Check() error {
	if err := r.Match.check(); err != nil {
		return fmt.Errorf("rule %s: %w", r, err)
	}
	if err := r.Action.check(); err != nil {
		return fmt.Errorf("rule %s: %w", r, err)
	}
	return nil
}

func (m Match) check() error {
	if !m.Kind.known() {
		return fmt.Errorf("unknown matcher kind %d", m.Kind)
	}
	if m.Kind != MatchCIDR && m.Prefix.IsValid() {
		return errors.New("a prefix on a matcher other than cidr")
	}
	switch m.Kind {
	case MatchDefault, MatchLocal:
		if m.Value != "" {
			return fmt.Errorf("%s takes no argument", m.Kind)
		}
	case MatchCIDR:
		p := m.Prefix
		switch {
		case m.Value != "":
			return errors.New("cidr has a prefix, not a value")
		case !p.IsValid() || p.Addr().Zone() != "":
			return fmt.Errorf("prefix %v", p)
		case p != p.Masked():
			return fmt.Errorf("prefix %v has host bits set", p)
		case p.Addr().Is6() && p.Overlaps(mappedRange) && p.Bits() >= mappedRange.Bits():
			return fmt.Errorf("prefix %v is inside %v: match IPv4 as IPv4", p, mappedRange)
		}
	case MatchGeoIP, MatchGeoSite:
		return CheckListName(m.Value)
	case MatchDomain, MatchDomainSuffix:
		return checkDomain(m.Value)
	}
	return nil
}

func (a Action) check() error {
	switch {
	case !a.Kind.known():
		return fmt.Errorf("unknown action kind %d", a.Kind)
	case a.Kind == ActionChain:
		return CheckChainName(a.Chain)
	case a.Chain != "":
		return fmt.Errorf("%s names a chain", a.Kind)
	}
	return nil
}

// CheckListName reports whether name can name a list (a geoip or geosite
// blob): 1-32 lowercase letters, digits and dashes, starting with a letter
// or digit.
func CheckListName(name string) error {
	if checkName(name, maxListName, true) {
		return nil
	}
	return fmt.Errorf("list name %q: use 1-%d lowercase letters, digits and dashes, starting with a letter or digit", name, maxListName)
}

// CheckChainName reports whether name can name a chain: as a list name.
func CheckChainName(name string) error {
	if checkName(name, maxChainName, true) {
		return nil
	}
	return fmt.Errorf("chain name %q: use 1-%d lowercase letters, digits and dashes, starting with a letter or digit", name, maxChainName)
}

// checkDomain accepts a lowercase ASCII domain without a trailing dot
// (IDNs in their xn-- form): labels of 1-63 letters, digits, dashes and
// underscores, no dash at either end.
func checkDomain(d string) error {
	if d == "" || len(d) > maxDomain {
		return fmt.Errorf("domain %q", d)
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > maxLabel || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain %q", d)
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return fmt.Errorf("domain %q", d)
		}
	}
	return nil
}

// rulesWellFormed is the readers' check: kinds are set (a reader keeps an
// unknown one and reports the rule as not enforced), chains are named
// once, and no chain exits through the node itself.
func (s *Section) rulesWellFormed() error {
	for i, r := range s.Rules {
		if r.Match.Kind == 0 || r.Action.Kind == 0 {
			return fmt.Errorf("rule %d: matcher or action unspecified", i)
		}
	}
	chains := make(map[string]bool, len(s.Chains))
	for _, c := range s.Chains {
		if c.Name == "" || chains[c.Name] {
			return fmt.Errorf("chain %q unnamed or listed twice", c.Name)
		}
		chains[c.Name] = true
		if c.Exit.IsZero() || c.Exit == s.Node.ID {
			return fmt.Errorf("chain %q: exit is zero or the node itself", c.Name)
		}
	}
	return nil
}

// validateRules is Build's check: every rule passes Check and refers only
// to what the section has (its chains, its named blobs), and the last one
// matches default; every chain's exit is a peer, and no two chains end at
// the same exit (WireGuard holds one session per exit and the path layer
// uses one path to it at a time, so two such chains could never carry
// traffic at once).
func (s *Section) validateRules() error {
	named := make(map[BlobKind]map[string]bool)
	for _, b := range s.Blobs {
		if b.Name == "" {
			continue
		}
		if named[b.Kind] == nil {
			named[b.Kind] = make(map[string]bool)
		}
		if named[b.Kind][b.Name] {
			return fmt.Errorf("two %v blobs named %q", b.Kind, b.Name)
		}
		named[b.Kind][b.Name] = true
	}
	peers := make(map[NodeID]bool, len(s.Peers))
	for _, p := range s.Peers {
		peers[p.ID] = true
	}
	chains := make(map[string]bool, len(s.Chains))
	exits := make(map[NodeID]string, len(s.Chains))
	for _, c := range s.Chains {
		if err := CheckChainName(c.Name); err != nil {
			return err
		}
		if !peers[c.Exit] {
			return fmt.Errorf("chain %s: exit %v is not a peer", c.Name, c.Exit)
		}
		if other, ok := exits[c.Exit]; ok {
			return fmt.Errorf("chains %s and %s end at the same exit", other, c.Name)
		}
		exits[c.Exit] = c.Name
		chains[c.Name] = true
	}
	for _, r := range s.Rules {
		if err := r.Check(); err != nil {
			return err
		}
		switch {
		case r.Action.Kind == ActionChain && !chains[r.Action.Chain]:
			return fmt.Errorf("rule %s: no chain %s", r, r.Action.Chain)
		case r.Match.NamesAList() && !named[listBlobKind(r.Match.Kind)][r.Match.Value]:
			return fmt.Errorf("rule %s: no %v blob named %s", r, listBlobKind(r.Match.Kind), r.Match.Value)
		}
	}
	if !EndsWithDefault(s.Rules) {
		return errors.New("rules: the last rule must match default, so every destination has an action")
	}
	if d := s.Presets.Domestic; d != "" && !named[BlobGeoIP][d] {
		return fmt.Errorf("presets: no geoip blob named %q", d)
	}
	if c := s.Presets.Chain; c != "" && !chains[c] {
		return fmt.Errorf("presets: no chain %q", c)
	}
	return nil
}

// listBlobKind is the blob kind a list-naming matcher's value names.
func listBlobKind(k MatchKind) BlobKind {
	if k == MatchGeoSite {
		return BlobGeoSite
	}
	return BlobGeoIP
}

// NamesAList reports whether the matcher matches by the name of a list
// blob (geoip, or geosite once specs carry them): the list it names must
// be declared.
func (m Match) NamesAList() bool { return m.Kind == MatchGeoIP || m.Kind == MatchGeoSite }

// EndsWithDefault reports whether the last rule matches default. An empty
// list passes: with no rules nothing enters the tunnel.
func EndsWithDefault(rules []Rule) bool {
	return len(rules) == 0 || rules[len(rules)-1].Match.Kind == MatchDefault
}

// MayEndAChain reports whether the node may be a chain's exit: only a
// server with egress on.
func (n *NodeSettings) MayEndAChain() bool {
	return n.Kind == NodeServer && n.AllowEgress
}

// chainsEndAtExits is Build's check across sections that every chain ends
// at a server that allows egress. A node outside the map (a shared node)
// is checked by the builder of the map that has it.
func chainsEndAtExits(recipients []Recipient) error {
	nodes := make(map[NodeID]*NodeSettings, len(recipients))
	for i := range recipients {
		n := &recipients[i].Section.Node
		nodes[n.ID] = n
	}
	for i, r := range recipients {
		for _, c := range r.Section.Chains {
			if exit, ok := nodes[c.Exit]; ok && !exit.MayEndAChain() {
				return fmt.Errorf("recipient %d: chain %s ends at %v, not a server that allows egress", i, c.Name, c.Exit)
			}
		}
	}
	return nil
}

func rulesToProto(s *Section, pb *netmapv1.Section) {
	for _, r := range s.Rules {
		value := r.Match.Value
		if r.Match.Kind == MatchCIDR {
			value = prefixString(r.Match.Prefix)
		}
		pb.Rules = append(pb.Rules, &netmapv1.Rule{
			Match: netmapv1.MatchKind(r.Match.Kind), Value: value,
			Action: netmapv1.ActionKind(r.Action.Kind), Chain: r.Action.Chain,
		})
	}
	for _, c := range s.Chains {
		pb.Chains = append(pb.Chains, &netmapv1.Chain{Name: c.Name, Exit: idBytes(c.Exit)})
	}
	if s.Presets != (RulePresets{}) {
		pb.Presets = &netmapv1.RulePresets{Domestic: s.Presets.Domestic, Chain: s.Presets.Chain}
	}
}

// rulesFromProto keeps unknown matcher and action kinds (the node reports
// such rules as not enforced); a cidr's prefix must be in canonical form.
func rulesFromProto(pb *netmapv1.Section, s *Section) error {
	for i, pr := range pb.GetRules() {
		r := Rule{
			Match:  Match{Kind: MatchKind(min(uint32(pr.GetMatch()), 255)), Value: pr.GetValue()},
			Action: Action{Kind: ActionKind(min(uint32(pr.GetAction()), 255)), Chain: pr.GetChain()},
		}
		if r.Match.Kind == MatchCIDR {
			p, err := parsePrefix(r.Match.Value)
			if err != nil {
				return fmt.Errorf("rule %d: %w", i, err)
			}
			r.Match.Prefix, r.Match.Value = p, ""
		}
		s.Rules = append(s.Rules, r)
	}
	for _, pc := range pb.GetChains() {
		exit, err := toArray[NodeID]("chain exit", pc.GetExit())
		if err != nil {
			return err
		}
		s.Chains = append(s.Chains, Chain{Name: pc.GetName(), Exit: exit})
	}
	if p := pb.GetPresets(); p != nil {
		s.Presets = RulePresets{Domestic: p.GetDomestic(), Chain: p.GetChain()}
	}
	return nil
}
