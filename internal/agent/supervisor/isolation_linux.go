//go:build linux && !android

package supervisor

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The root namespace is the only place the spaces' veths meet, so it is
// where they are kept apart (PRD "Isolation"): a worker holds NET_ADMIN in
// its own namespace and can route anything at its veth, so the separation
// can't rely on the spaces' routes. The supervisor's table, in the root
// namespace:
//
//	table inet thinkpol-supervisor {
//		chain forward {
//			type filter hook forward priority filter; policy accept;
//			iifname "tp-space*" drop
//			oifname "tp-space*" drop
//		}
//		chain input {
//			type filter hook input priority filter; policy accept;
//			iifname "tp-space*" ct state established,related accept
//			iifname "tp-space*" icmpv6 type nd-neighbor-solicit accept
//			iifname "tp-space*" icmpv6 type nd-neighbor-advert accept
//			iifname "tp-space*" drop
//		}
//	}
//
// Nothing is forwarded from or to a space: not to another space, not to the
// internet. Egress (TP-014) opens exactly the forwarding it masquerades, in
// this table, ahead of the drops. A space reaches nothing of the root
// namespace's own either, past neighbour discovery and replies to what the
// root namespace started.

func installIsolation() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	// Adding first makes the delete succeed whether or not a dead
	// supervisor left the table; the batch replaces it atomically.
	c.AddTable(table)
	c.DelTable(table)
	c.AddTable(table)
	accept := nftables.ChainPolicyAccept
	forward := c.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	})
	input := c.AddChain(&nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	})
	rule := func(chain *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	acceptVerdict := &expr.Verdict{Kind: expr.VerdictAccept}

	rule(forward, append(spaceLink(expr.MetaKeyIIFNAME), drop)...)
	rule(forward, append(spaceLink(expr.MetaKeyOIFNAME), drop)...)

	established := binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	rule(input, append(spaceLink(expr.MetaKeyIIFNAME),
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: established, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		acceptVerdict,
	)...)
	for _, typ := range []byte{135, 136} { // neighbour solicitation, advertisement
		rule(input, append(spaceLink(expr.MetaKeyIIFNAME),
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{typ}},
			acceptVerdict,
		)...)
	}
	rule(input, append(spaceLink(expr.MetaKeyIIFNAME), drop)...)

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: install table %s: %w", TableName, err)
	}
	return nil
}

// spaceLink matches packets whose interface (key: in or out) is a space's
// veth end: a compare on the name's first bytes is how nft matches
// "tp-space*".
func spaceLink(key expr.MetaKey) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(LinkPrefix)},
	}
}

// removeIsolation deletes the supervisor's table, if it is there.
func removeIsolation() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	c.AddTable(table)
	c.DelTable(table)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: remove table %s: %w", TableName, err)
	}
	return nil
}
