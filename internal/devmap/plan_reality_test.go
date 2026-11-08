package devmap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/reality"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const realitySpec = `nodes:
  - name: server-1
    kind: server
    endpoints:
      - reality://192.0.2.10:443
      - udp://192.0.2.10:4500
    reality:
      target: ${TARGET}
      server_names: [camouflage.example.net, www.example.net]
    ingress: true
  - {name: device-a, kind: device}
paths:
  - [device-a, server-1]
`

// camouflageSite is a TLS 1.3 site for camouflage.example.net and
// www.example.net on loopback, with a self-signed certificate; roots
// trusts it.
func camouflageSite(t *testing.T) (addr string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"camouflage.example.net", "www.example.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(leaf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				_, _ = c.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String(), roots
}

// What `dev map` writes for reality links a node and a device: the
// server's listener settings and inbound short id, and the device's
// endpoint (credential, server name, the listener's public key), as the
// map gives them, make a link the server accepts as the device.
func TestRealityEndpointsLinkANodeAndADevice(t *testing.T) {
	site, roots := camouflageSite(t)
	f := newFixture(t, "reality.yaml", []byte(realitySpec), map[string]string{"TARGET": site})
	_, secs, _ := f.sections(t, 1)
	server, device := secs["server-1"], secs["device-a"]

	var listener netmap.Listener
	for _, l := range server.Node.Listeners {
		if l.Transport == reality.Name {
			listener = l
		}
	}
	if listener.Settings == nil {
		t.Fatalf("no reality listener settings in %+v", server.Node.Listeners)
	}
	var inbound []transport.PeerLink
	for _, in := range server.Inbound {
		if in.Transport == reality.Name {
			inbound = append(inbound, transport.PeerLink{Peer: transport.Identity{Node: transport.NodeID(in.Peer)}, Verifier: in.Credential, Settings: in.Settings})
		}
	}
	var endpoint netmap.Endpoint
	for _, e := range device.Links[0].Endpoints {
		if e.Transport == reality.Name {
			endpoint = e
		}
	}
	if len(inbound) != 1 || len(endpoint.Credential) != reality.ShortIDSize {
		t.Fatalf("inbound %+v, endpoint %+v", inbound, endpoint)
	}

	tr := reality.New(reality.Options{TrustTargetRoots: roots})
	l, err := tr.Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listener.Settings},
		transport.Admission{Peers: transport.NewPeerTable(inbound...)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		link, err := tr.Dial(ctx, l.Addr().String(), transport.DialConfig{Credential: endpoint.Credential, Settings: endpoint.Settings})
		if err != nil {
			t.Error(err)
			return
		}
		<-ctx.Done()
		_ = link.Close()
	}()
	_, id, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id.Node != transport.NodeID(device.Node.ID) {
		t.Fatalf("accepted %s, want device-a %s", id, device.Node.ID)
	}
}
