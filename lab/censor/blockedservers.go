package censor

import (
	"net/netip"
	"sync"
)

// blockedServers is the TCP servers an active module found out, by
// address and port, with why: its passive half blocks every connection to
// or from one from then on, as the Great Firewall blocks a server its
// prober confirmed. The active half adds to it from its own goroutines.
type blockedServers struct {
	mu      sync.RWMutex
	servers map[netip.AddrPort]string
}

func (b *blockedServers) add(server netip.AddrPort, why string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.servers == nil {
		b.servers = map[netip.AddrPort]string{}
	}
	if _, ok := b.servers[server]; !ok {
		b.servers[server] = why
	}
}

// of says why a flow's connection is blocked: either of its ends is a
// blocked server.
func (b *blockedServers) of(k FlowKey) (string, bool) {
	if k.Proto != ProtoTCP {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, end := range []netip.AddrPort{netip.AddrPortFrom(k.Dst, k.DstPort), netip.AddrPortFrom(k.Src, k.SrcPort)} {
		if why, ok := b.servers[end]; ok {
			return why, true
		}
	}
	return "", false
}
