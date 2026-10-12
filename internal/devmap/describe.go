package devmap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// DescribeHeader prints a verified map's header.
func DescribeHeader(w io.Writer, m *netmap.Map) error {
	h := m.Header()
	p := printer{w: w}
	p.line(0, "space: %v", h.SpaceID)
	p.line(0, "key epoch: %d", h.KeyEpoch)
	p.line(0, "version: %d", h.Version)
	p.line(0, "signing key: %s", hex.EncodeToString(h.SigningKey))
	p.line(0, "recovery key: %s", hex.EncodeToString(h.RecoveryKey))
	p.blobs(0, h.Blobs)
	p.line(0, "sections: %d", m.SectionCount())
	p.line(0, "size: %d bytes", len(m.Bytes()))
	return p.err
}

// DescribeSection prints a node's section, naming node ids it knows.
// Credentials are shown by length and fingerprint, never in full.
func DescribeSection(w io.Writer, s netmap.Section, names Names) error {
	p := printer{w: w}
	n := s.Node
	p.line(0, "node: %s", names.Of(n.ID))
	p.line(0, "kind: %v", n.Kind)
	if n.Kind == netmap.NodeServer {
		p.line(0, "ingress: %s, egress: %s", onOff(n.AllowIngress), onOff(n.AllowEgress))
	}
	p.line(0, "min reader: %d", s.MinReader)
	p.line(0, "ipv4: %v in %v", n.IPv4, n.IPv4Network)
	p.line(0, "ipv6: %v in %v", n.IPv6, n.IPv6Network)
	if s.SpaceName != "" || n.Name != "" {
		p.line(0, "overlay name: %s.%s.internal", n.Name, s.SpaceName)
	}
	p.list(0, "listeners", len(n.Listeners), func(i int) {
		l := n.Listeners[i]
		p.line(1, "- %s://%v%s", l.Transport, l.Address, settings(l.Settings))
	})
	p.list(0, "peers", len(s.Peers), func(i int) {
		peer := s.Peers[i]
		p.line(1, "- id: %s", names.Of(peer.ID))
		if peer.Name != "" {
			p.line(2, "name: %s", peer.Name)
		}
		p.line(2, "wireguard key: %v", peer.WireGuardKey)
		addrs := make([]string, len(peer.Addresses))
		for j, a := range peer.Addresses {
			addrs[j] = a.String()
		}
		p.line(2, "addresses: %s", strings.Join(addrs, ", "))
		p.line(2, "first hops:")
		for _, path := range peer.Paths {
			p.line(3, "- %s", names.Of(path.FirstHop))
		}
	})
	p.list(0, "links", len(s.Links), func(i int) {
		l := s.Links[i]
		p.line(1, "- peer: %s", names.Of(l.Peer))
		p.line(2, "endpoints:")
		for _, e := range l.Endpoints {
			p.line(3, "- %s://%v, credential %s%s", e.Transport, e.Address, fingerprint(e.Credential), settings(e.Settings))
		}
	})
	p.list(0, "inbound", len(s.Inbound), func(i int) {
		in := s.Inbound[i]
		refused := ""
		if !n.AcceptsInbound(in) {
			refused = " (refused: ingress off)"
		}
		p.line(1, "- peer: %s, %v%s", names.Of(in.Peer), in.PeerKind, refused)
		p.line(2, "%s, credential %s%s", in.Transport, fingerprint(in.Credential), settings(in.Settings))
	})
	p.list(0, "routes", len(s.Routes), func(i int) {
		r := s.Routes[i]
		p.line(1, "- to: %s", names.Of(r.Destination))
		p.line(2, "next hops:")
		for _, h := range r.NextHops {
			p.line(3, "- %s", names.Of(h))
		}
	})
	p.blobs(0, s.Blobs)
	if len(s.Rules) > 0 {
		p.list(0, "rules", len(s.Rules), func(i int) { p.line(1, "- %s", s.Rules[i]) })
		p.list(0, "chains", len(s.Chains), func(i int) {
			p.line(1, "- %s: exit %s", s.Chains[i].Name, names.Of(s.Chains[i].Exit))
		})
	}
	return p.err
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// fingerprint shows a credential well enough to match the two ends of a
// link without printing the secret.
func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%d bytes, sha256 %x…", len(b), sum[:4])
}

func settings(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf(", settings %d bytes", len(b))
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(indent int, format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, strings.Repeat("  ", indent)+format+"\n", args...)
	}
}

func (p *printer) list(indent int, name string, n int, item func(int)) {
	if n == 0 {
		p.line(indent, "%s: none", name)
		return
	}
	p.line(indent, "%s:", name)
	for i := range n {
		item(i)
	}
}

func (p *printer) blobs(indent int, blobs []netmap.BlobRef) {
	p.list(indent, "blobs", len(blobs), func(i int) {
		b := blobs[i]
		name := ""
		if b.Name != "" {
			name = " " + b.Name
		}
		p.line(indent+1, "- %v%s: sha256 %x, %d bytes", b.Kind, name, b.SHA256, b.Size)
	})
}
