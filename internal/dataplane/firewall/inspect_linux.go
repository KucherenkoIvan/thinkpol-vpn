//go:build linux && !android

package firewall

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// InspectIPv6Guard reads the guard's table in the calling thread's
// network namespace as the kernel holds it, for diagnostics: its flags,
// chains, rules with their counters and the exempt set. It changes
// nothing, and works whether or not a guard runs.
func InspectIPv6Guard(context.Context) routetable.GuardReport {
	return (&IPv6Guard{netns: -1}).inspect()
}

// InspectIPv6GuardInNamespace is InspectIPv6Guard in the network namespace
// at path.
func InspectIPv6GuardInNamespace(path string) routetable.GuardReport {
	g, err := NewIPv6GuardInNamespace(path)
	if err != nil {
		return routetable.GuardReport{Unreadable: err.Error()}
	}
	defer func() { _ = unix.Close(g.netns) }()
	return g.inspect()
}

func (g *IPv6Guard) inspect() routetable.GuardReport {
	r := routetable.GuardReport{Where: "nftables table inet " + GuardTable}
	c, err := g.conn()
	if err != nil {
		r.Unreadable = err.Error()
		return r
	}
	t, err := readTable(c, GuardTable)
	if err != nil {
		r.Unreadable = err.Error()
		return r
	}
	if t.table == nil {
		return r
	}
	r.Present, r.NFTables, r.Rules, r.RulesUnreadable = true, t.nft, t.rules, t.rulesUnreadable
	r.Exempt, r.ExemptUnreadable = exemptSet(c, t.table)
	return r
}

// InspectKillSwitch reads the kill switch's table in the calling
// thread's network namespace as the kernel holds it, for diagnostics:
// its flags, chains, rules with their counters and the sizes of its
// sets. It changes nothing, and works whether or not a kill switch runs.
func InspectKillSwitch(context.Context) KillSwitchReport {
	return NewKillSwitch().inspect()
}

// InspectKillSwitchInNamespace is InspectKillSwitch in the network
// namespace at path.
func InspectKillSwitchInNamespace(path string) KillSwitchReport {
	k, err := NewKillSwitchInNamespace(path)
	if err != nil {
		return KillSwitchReport{Unreadable: err.Error()}
	}
	defer func() { _ = unix.Close(k.netns) }()
	return k.inspect()
}

func (k *KillSwitch) inspect() KillSwitchReport {
	r := KillSwitchReport{Where: "nftables table inet " + KillSwitchTable}
	c, err := nftConn(k.netns)
	if err != nil {
		r.Unreadable = err.Error()
		return r
	}
	t, err := readTable(c, KillSwitchTable)
	if err != nil {
		r.Unreadable = err.Error()
		return r
	}
	if t.table == nil {
		return r
	}
	r.Present, r.NFTables, r.Rules, r.RulesUnreadable = true, t.nft, t.rules, t.rulesUnreadable
	sets, err := c.GetSets(t.table)
	if err != nil {
		r.SetsUnreadable = "nftables sets: " + err.Error()
		return r
	}
	for _, set := range sets {
		r.Sets = append(r.Sets, setSize(c, set))
	}
	return r
}

// setSize counts set's intervals: an interval set dumps each as its first
// address and, flagged as its end, the address after its last (and may
// flag the gap below the first so), so only the starts count.
func setSize(c *nftables.Conn, set *nftables.Set) KillSwitchSetReport {
	out := KillSwitchSetReport{Name: set.Name}
	elems, err := c.GetSetElements(set)
	if err != nil {
		out.Unreadable = fmt.Sprintf("nftables set %s: %v", set.Name, err)
		return out
	}
	for _, e := range elems {
		if !e.IntervalEnd {
			out.Entries++
		}
	}
	return out
}

// tableReading is a table as readTable found it; table is nil when the
// namespace has none by its name.
type tableReading struct {
	table           *nftables.Table
	nft             *routetable.NFTablesReport
	rules           []routetable.GuardRuleReport
	rulesUnreadable string
}

// readTable reads the inet table name: its flags, chains, and rules with
// their counters. err is set when the tables can't be listed at all.
func readTable(c *nftables.Conn, name string) (tableReading, error) {
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if noNFTables(err) {
			return tableReading{}, fmt.Errorf("no nf_tables in the kernel: %w", err)
		}
		return tableReading{}, fmt.Errorf("nftables: %w", err)
	}
	i := slices.IndexFunc(tables, func(t *nftables.Table) bool { return t.Name == name })
	if i < 0 {
		return tableReading{}, nil
	}
	table := tables[i]
	r := tableReading{table: table, nft: &routetable.NFTablesReport{Dormant: tableFlags(table)&unix.NFT_TABLE_F_DORMANT != 0}}
	chains, err := tableChains(c, name)
	if err != nil {
		r.nft.ChainsUnreadable = "nftables chains: " + err.Error()
		r.rulesUnreadable = r.nft.ChainsUnreadable
	}
	for _, ch := range chains {
		r.nft.Chains = append(r.nft.Chains, chainReport(ch))
		if r.rulesUnreadable != "" {
			continue
		}
		rules, err := c.GetRules(table, ch)
		if err != nil {
			r.rules, r.rulesUnreadable = nil, fmt.Sprintf("nftables rules of chain %s: %v", ch.Name, err)
			continue
		}
		for _, rule := range rules {
			r.rules = append(r.rules, ruleReport(ch.Name, rule.Exprs))
		}
	}
	return r, nil
}

// tableFlags are the table's flags. The kernel sends them big-endian, and
// nftables decodes them in the host's order.
func tableFlags(t *nftables.Table) uint32 {
	return binary.BigEndian.Uint32(binary.NativeEndian.AppendUint32(nil, t.Flags))
}

func chainReport(ch *nftables.Chain) routetable.NFTChainReport {
	out := routetable.NFTChainReport{Name: ch.Name}
	if ch.Hooknum != nil {
		out.Hook = hookName(*ch.Hooknum)
	}
	if ch.Priority != nil {
		out.Priority = int(*ch.Priority)
	}
	if ch.Policy != nil {
		out.Policy = "drop"
		if *ch.Policy == nftables.ChainPolicyAccept {
			out.Policy = "accept"
		}
	}
	return out
}

func hookName(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	}
	return "hook " + strconv.Itoa(int(h))
}

// exemptSet reads the guard's interval set as the fewest prefixes. An
// interval set dumps each interval as its first address and, flagged as
// its end, the address after its last; an interval without an end runs to
// the top. A table without the set exempts nothing.
func exemptSet(c *nftables.Conn, table *nftables.Table) ([]netip.Prefix, string) {
	set, err := c.GetSetByName(table, guardSet)
	if errors.Is(err, unix.ENOENT) {
		return nil, ""
	}
	if err != nil {
		return nil, fmt.Sprintf("nftables set %s: %v", guardSet, err)
	}
	elems, err := c.GetSetElements(set)
	if err != nil {
		return nil, fmt.Sprintf("nftables set %s: %v", guardSet, err)
	}
	type bound struct {
		a   netip.Addr
		end bool
	}
	bounds := make([]bound, 0, len(elems))
	for _, e := range elems {
		a, ok := netip.AddrFromSlice(e.Key)
		if !ok || !a.Is6() || a.Is4In6() {
			return nil, fmt.Sprintf("nftables set %s holds %x", guardSet, e.Key)
		}
		bounds = append(bounds, bound{a, e.IntervalEnd})
	}
	// An end sorts before a start at the same address: it closes the
	// interval before, which the next one starts right after.
	slices.SortFunc(bounds, func(x, y bound) int {
		if c := x.a.Compare(y.a); c != 0 {
			return c
		}
		return cmp.Compare(boolInt(!x.end), boolInt(!y.end))
	})
	var b lists.Builder
	var first netip.Addr
	open := false
	for _, bd := range bounds {
		switch {
		case !bd.end && !open:
			first, open = bd.a, true
		case bd.end && open:
			if err := b.AddRange(first, bd.a.Prev()); err != nil {
				return nil, fmt.Sprintf("nftables set %s: %v", guardSet, err)
			}
			open = false
		case bd.end && bd.a == netip.IPv6Unspecified():
			// The kernel may mark the gap below the first interval so.
		default:
			return nil, fmt.Sprintf("nftables set %s: interval bounds out of order at %s", guardSet, bd.a)
		}
	}
	if open {
		if err := b.AddRange(first, netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); err != nil {
			return nil, fmt.Sprintf("nftables set %s: %v", guardSet, err)
		}
	}
	s, _ := b.Build()
	return s.Prefixes(), ""
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ruleReport is a rule as the kernel holds it: its expressions rendered
// nft-like, and its counter's values.
func ruleReport(chain string, exprs []expr.Any) routetable.GuardRuleReport {
	r := routetable.GuardRuleReport{Chain: chain, Text: ruleText(exprs)}
	for _, x := range exprs {
		if c, ok := x.(*expr.Counter); ok {
			r.Counted = true
			r.Packets += c.Packets
			r.Bytes += c.Bytes
		}
	}
	return r
}

// ruleText renders exprs nft-like, as far as the guard's and the kill
// switch's own rules need it (the text is a reading aid, not nft input):
// what a meta key, a conntrack key or a payload loads, then compared, looked up
// or ranged, and the statements. A raw payload is nft's `@base,offset,len`
// in bits; an expression it doesn't know shows as its type. A counter
// shows without its values, which the report carries apart.
func ruleText(exprs []expr.Any) string {
	var words []string
	loaded := ""
	for _, x := range exprs {
		switch v := x.(type) {
		case *expr.Meta:
			loaded = metaName(v.Key)
			if v.SourceRegister {
				words = append(words, "meta "+loaded+" set")
			} else {
				words = append(words, "meta "+loaded)
			}
		case *expr.Ct:
			loaded = ctName(v.Key)
			words = append(words, "ct "+loaded)
		case *expr.Payload:
			loaded = "payload"
			words = append(words, fmt.Sprintf("@%s,%d,%d", payloadBase(v.Base), v.Offset*8, v.Len*8))
		case *expr.Cmp:
			if op := cmpOp(v.Op); op != "" {
				words = append(words, op)
			}
			words = append(words, dataText(loaded, v.Data))
		case *expr.Range:
			if op := cmpOp(v.Op); op != "" {
				words = append(words, op)
			}
			words = append(words, dataText(loaded, v.FromData)+"-"+dataText(loaded, v.ToData))
		case *expr.Lookup:
			if v.Invert {
				words = append(words, "!=")
			}
			words = append(words, "@"+v.SetName)
		case *expr.Counter:
			words = append(words, "counter")
		case *expr.Reject:
			words = append(words, rejectText(v))
		case *expr.Verdict:
			words = append(words, verdictText(v))
		default:
			words = append(words, strings.TrimPrefix(fmt.Sprintf("%T", x), "*expr."))
		}
	}
	return strings.Join(words, " ")
}

func metaName(k expr.MetaKey) string {
	switch k {
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyMARK:
		return "mark"
	}
	return "key" + strconv.Itoa(int(k))
}

func ctName(k expr.CtKey) string {
	switch k {
	case expr.CtKeyDIRECTION:
		return "direction"
	case expr.CtKeySTATE:
		return "state"
	}
	return "key" + strconv.Itoa(int(k))
}

func payloadBase(b expr.PayloadBase) string {
	switch b {
	case expr.PayloadBaseLLHeader:
		return "ll"
	case expr.PayloadBaseNetworkHeader:
		return "nh"
	case expr.PayloadBaseTransportHeader:
		return "th"
	}
	return "base" + strconv.Itoa(int(b))
}

func cmpOp(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpEq:
		return ""
	case expr.CmpOpNeq:
		return "!="
	case expr.CmpOpLt:
		return "<"
	case expr.CmpOpLte:
		return "<="
	case expr.CmpOpGt:
		return ">"
	case expr.CmpOpGte:
		return ">="
	}
	return "op" + strconv.Itoa(int(op))
}

// dataText renders a comparison's data by what was loaded to compare it
// with: interface names as strings, families, protocols and conntrack
// directions by name, a mark in hex, an address as one, other numbers
// big-endian.
func dataText(loaded string, d []byte) string {
	switch loaded {
	case "oifname", "iifname":
		if i := slices.Index(d, 0); i >= 0 {
			d = d[:i]
		}
		return strconv.Quote(string(d))
	case "nfproto":
		if len(d) == 1 {
			switch d[0] {
			case unix.NFPROTO_IPV4:
				return "ipv4"
			case unix.NFPROTO_IPV6:
				return "ipv6"
			}
		}
	case "l4proto":
		if len(d) == 1 {
			switch d[0] {
			case unix.IPPROTO_TCP:
				return "tcp"
			case unix.IPPROTO_UDP:
				return "udp"
			case unix.IPPROTO_ICMPV6:
				return "ipv6-icmp"
			case unix.IPPROTO_ICMP:
				return "icmp"
			}
		}
	case "direction":
		if len(d) == 1 {
			switch d[0] {
			case 0: // IP_CT_DIR_ORIGINAL
				return "original"
			case 1: // IP_CT_DIR_REPLY
				return "reply"
			}
		}
	case "mark":
		if len(d) == 4 {
			return fmt.Sprintf("0x%08x", binary.NativeEndian.Uint32(d))
		}
	}
	if a, ok := netip.AddrFromSlice(d); ok && len(d) == 16 {
		return a.String()
	}
	if len(d) <= 8 {
		var n uint64
		for _, b := range d {
			n = n<<8 | uint64(b)
		}
		return strconv.FormatUint(n, 10)
	}
	return fmt.Sprintf("0x%x", d)
}

func rejectText(r *expr.Reject) string {
	switch r.Type {
	case unix.NFT_REJECT_TCP_RST:
		return "reject with tcp reset"
	case unix.NFT_REJECT_ICMPX_UNREACH:
		switch r.Code {
		case unix.NFT_REJECT_ICMPX_NO_ROUTE:
			return "reject with icmpx no-route"
		case unix.NFT_REJECT_ICMPX_PORT_UNREACH:
			return "reject with icmpx port-unreachable"
		case unix.NFT_REJECT_ICMPX_HOST_UNREACH:
			return "reject with icmpx host-unreachable"
		case unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED:
			return "reject with icmpx admin-prohibited"
		}
	}
	return fmt.Sprintf("reject type %d code %d", r.Type, r.Code)
}

func verdictText(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictJump:
		return "jump " + v.Chain
	case expr.VerdictGoto:
		return "goto " + v.Chain
	}
	return "verdict " + strconv.Itoa(int(v.Kind))
}
