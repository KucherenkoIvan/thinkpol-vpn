//go:build linux && !android

package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// SpaceTableName is the supervisor's nftables table (family inet) inside
// each space's namespace, where the space's egress is forwarded and SNATed.
const SpaceTableName = "thinkpol-space"

// spaceEgress is what a space's namespace table forwards: whether the space
// has egress at all (granted, with an uplink), and the families it may send.
type spaceEgress struct {
	on     bool
	family [2]bool
}

// applySpaceTable replaces the space's own egress table in the namespace ns:
//
//	table inet thinkpol-space {
//	  chain forward { hook forward priority filter; policy drop;
//	    ct state established,related accept
//	    per family with egress: oifname veth0 meta nfproto <family> accept
//	    per family without, when the space has egress:
//	      oifname veth0 meta nfproto <family> reject with icmpx no-route }
//	  chain postrouting { type nat hook postrouting priority srcnat;
//	    oifname veth0 ip saddr != <transit IPv4> snat to <transit IPv4>:MasqueradePorts fully-random
//	    oifname veth0 ip6 saddr != <transit IPv6> snat to [<transit IPv6>]:MasqueradePorts fully-random }
//	}
//
// Only what the worker's engine delivers to its TUN for the internet is
// forwarded (it does so only on an exit), always out of veth0 to the root
// namespace, which sees nothing but the space's transit address and
// enforces the same egress again in its own table: the worker owns this
// table's namespace and could change it. A family the node can't egress
// is refused at once, so clients fall back to the other (IPv6 on a VPS
// without it) instead of timing out; without egress at all, forwarded
// traffic is dropped. The SNAT picks a fully random source port within the
// range the root's masquerade keeps.
func applySpaceTable(ns *os.File, t transit, e spaceEgress) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(ns.Fd())))
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: SpaceTableName}
	c.AddTable(table)
	c.DelTable(table)
	c.AddTable(table)
	policyDrop, policyAccept := nftables.ChainPolicyDrop, nftables.ChainPolicyAccept
	forward := c.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policyDrop,
	})
	nat := c.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &policyAccept,
	})
	add := func(chain *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}

	add(forward, established(nil)...)
	if e.on {
		for i, p := range t.space {
			out := append(linkExact(expr.MetaKeyOIFNAME, SpaceInterface), family(p.Addr())...)
			if e.family[i] {
				add(forward, append(out, &expr.Verdict{Kind: expr.VerdictAccept})...)
			} else {
				add(forward, append(out, &expr.Counter{},
					&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_NO_ROUTE})...)
			}
		}
	}
	for _, p := range t.space {
		add(nat, snat(p.Addr())...)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: the space's egress table: %w", err)
	}
	return nil
}

// snat is "oifname veth0; nfproto == a's family; saddr != a; snat to
// a:MasqueradePorts fully-random".
func snat(a netip.Addr) []expr.Any {
	nfproto := uint32(unix.NFPROTO_IPV6)
	if a.Is4() {
		nfproto = unix.NFPROTO_IPV4
	}
	return append(append(linkExact(expr.MetaKeyOIFNAME, SpaceInterface), family(a)...),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: srcOffset(a), Len: uint32(a.BitLen() / 8)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: a.AsSlice()},
		&expr.Immediate{Register: 1, Data: a.AsSlice()},
		&expr.Immediate{Register: 2, Data: binary.BigEndian.AppendUint16(nil, MasqueradePorts[0])},
		&expr.Immediate{Register: 3, Data: binary.BigEndian.AppendUint16(nil, MasqueradePorts[1])},
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: nfproto, RegAddrMin: 1, RegProtoMin: 2, RegProtoMax: 3, FullyRandom: true},
	)
}

// flushFlows deletes the conntrack entries a slot's transit addresses
// started, so a changed egress (or a reused slot) carries none of its old
// flows on.
func flushFlows(t transit) error {
	var errs []error
	for _, p := range t.space {
		f := &netlink.ConntrackFilter{}
		if err := f.AddIP(netlink.ConntrackOrigSrcIP, net.IP(p.Addr().AsSlice())); err != nil {
			return err
		}
		fam := netlink.InetFamily(unix.AF_INET6)
		if p.Addr().Is4() {
			fam = unix.AF_INET
		}
		if _, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam, f); err != nil {
			errs = append(errs, fmt.Errorf("conntrack: flush %v: %w", p.Addr(), err))
		}
	}
	return errors.Join(errs...)
}

// on reports whether each family's forwarding is on.
func (f *rootForwarding) on() [2]bool {
	var out [2]bool
	for i, key := range forwardingKeys {
		v, err := readSysctl(key)
		out[i] = err == nil && v == "1"
	}
	return out
}
