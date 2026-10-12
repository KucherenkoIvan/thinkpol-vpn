//go:build linux && !android

package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// SpaceTableName is the supervisor's nftables table (family inet) inside
// each space's namespace, where the space's egress is forwarded and SNATed.
const SpaceTableName = "thinkpol-space"

// applySpaceTable replaces the space's own egress table in the namespace ns:
//
//	table inet thinkpol-space {
//	  chain forward { hook forward priority filter; policy drop;
//	    ct state established,related accept
//	    per family with egress: oifname veth0 meta nfproto <family> accept
//	    per family without, when the space has egress:
//	      oifname veth0 meta nfproto <family> reject with icmpx no-route }
//	  chain postrouting { type nat hook postrouting priority srcnat;
//	    oifname veth0 ip saddr != <transit IPv4> snat to <transit IPv4>
//	    oifname veth0 ip6 saddr != <transit IPv6> snat to <transit IPv6> }
//	}
//
// Only what the worker's engine delivers to its TUN for the internet is
// forwarded (it does so only on an exit), always out of veth0 to the root
// namespace, which sees nothing but the space's transit address and
// enforces the same egress again in its own table: the worker owns this
// table's namespace and could change it. A family the node can't egress
// is refused at once, so clients fall back to the other (IPv6 on a VPS
// without it) instead of timing out; without egress at all, forwarded
// traffic is dropped.
func applySpaceTable(ns *os.File, t transit, e Egress) error {
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
	if e.Uplink != "" {
		for _, fam := range []struct {
			on   bool
			addr netip.Addr
		}{{e.IPv4, t.space[0].Addr()}, {e.IPv6, t.space[1].Addr()}} {
			out := append(linkExact(expr.MetaKeyOIFNAME, SpaceInterface), family(fam.addr)...)
			if fam.on {
				add(forward, append(out, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept})...)
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

// snat is "oifname veth0; nfproto == a's family; saddr != a; snat to a".
func snat(a netip.Addr) []expr.Any {
	nfproto := uint32(unix.NFPROTO_IPV6)
	if a.Is4() {
		nfproto = unix.NFPROTO_IPV4
	}
	return append(append(linkExact(expr.MetaKeyOIFNAME, SpaceInterface), family(a)...),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: srcOffset(a), Len: uint32(a.BitLen() / 8)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: a.AsSlice()},
		&expr.Immediate{Register: 1, Data: a.AsSlice()},
		&expr.Counter{},
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: nfproto, RegAddrMin: 1},
	)
}

// rootForwarding turns on the root namespace's forwarding sysctls the
// spaces' egress and dials need, and remembers what it changed so Close
// can put it back. A node that already forwards (provisioning sets it up,
// and so do container runtimes) is left as it is. IPv6 forwarding makes
// Linux ignore router advertisements on interfaces with accept_ra 1, which
// would cost an RA-configured VPS its IPv6 default route; such interfaces
// get accept_ra 2 first.
type rootForwarding struct {
	mu    sync.Mutex
	saved []sysctlValue // in the order they were changed
}

type sysctlValue struct{ key, value string }

// procSys is where the root namespace's sysctls are (the supervisor's own
// /proc: it runs in the root namespace).
const procSys = "/proc/sys"

// ensure turns forwarding on for the families rules send on. A failure is
// logged, not returned: the tables are in place, and egress then fails
// closed.
func (f *rootForwarding) ensure(rules []slotRule, log *slog.Logger) {
	var v4, v6 bool
	for _, r := range rules {
		if r.egress.Uplink != "" {
			v4, v6 = v4 || r.egress.IPv4, v6 || r.egress.IPv6
		}
		for _, d := range r.dials {
			v4, v6 = v4 || d.Addr().Unmap().Is4(), v6 || !d.Addr().Unmap().Is4()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v4 {
		if err := f.set("net/ipv4/ip_forward", "1"); err != nil {
			log.Warn("IPv4 forwarding is off and can't be turned on: no IPv4 egress or dials", "err", err)
		}
	}
	if v6 {
		if err := f.forward6(); err != nil {
			log.Warn("IPv6 forwarding is off and can't be turned on: no IPv6 egress or dials", "err", err)
		}
	}
}

func (f *rootForwarding) forward6() error {
	if v, err := readSysctl("net/ipv6/conf/all/forwarding"); err != nil || v == "1" {
		return err
	}
	confs, err := os.ReadDir(filepath.Join(procSys, "net/ipv6/conf"))
	if err != nil {
		return err
	}
	for _, conf := range confs {
		if conf.Name() == "all" {
			continue
		}
		key := "net/ipv6/conf/" + conf.Name() + "/accept_ra"
		if v, err := readSysctl(key); err == nil && v == "1" {
			if err := f.set(key, "2"); err != nil {
				return err
			}
		}
	}
	return f.set("net/ipv6/conf/all/forwarding", "1")
}

// set writes value to key unless it holds it already, remembering the
// first value it replaced.
func (f *rootForwarding) set(key, value string) error {
	was, err := readSysctl(key)
	if err != nil {
		return err
	}
	if was == value {
		return nil
	}
	if err := os.WriteFile(filepath.Join(procSys, key), []byte(value), 0); err != nil {
		return fmt.Errorf("sysctl %s: %w", key, err)
	}
	f.saved = append(f.saved, sysctlValue{key, was})
	return nil
}

// restore puts back what ensure changed, newest first. An interface gone
// meanwhile has nothing to restore.
func (f *rootForwarding) restore() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for i := len(f.saved) - 1; i >= 0; i-- {
		v := f.saved[i]
		err := os.WriteFile(filepath.Join(procSys, v.key), []byte(v.value), 0)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("restore sysctl %s: %w", v.key, err))
		}
	}
	f.saved = nil
	return errors.Join(errs...)
}

func readSysctl(key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(procSys, key))
	if err != nil {
		return "", fmt.Errorf("sysctl %s: %w", key, err)
	}
	return strings.TrimSpace(string(b)), nil
}
