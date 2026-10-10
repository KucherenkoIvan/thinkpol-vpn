package path_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

// wgEnd is a real wireguard-go device whose only network is a path.Bind.
type wgEnd struct {
	name string
	ip   netip.Addr
	key  *ecdh.PrivateKey
	tun  *tuntest.ChannelTUN
	bind *path.Bind
	dev  *device.Device
}

func (f *fabric) wireguard(name, ip string, p path.Peer) *wgEnd {
	f.t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	e := &wgEnd{name: name, ip: netip.MustParseAddr(ip), key: key, tun: tuntest.NewChannelTUN(), bind: f.node(name).NewBind()}
	if err := e.bind.SetPeers([]path.Peer{p}); err != nil {
		f.t.Fatal(err)
	}
	e.dev = device.NewDevice(e.tun.TUN(), e.bind, device.NewLogger(device.LogLevelSilent, ""))
	f.t.Cleanup(e.dev.Close)
	return e
}

// pair configures two ends as each other's only peer, with the peer's node
// id as WireGuard's endpoint, and brings them up.
func pair(t *testing.T, a, b *wgEnd) {
	t.Helper()
	for _, e := range []struct{ own, other *wgEnd }{{a, b}, {b, a}} {
		cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\n",
			hex.EncodeToString(e.own.key.Bytes()), hex.EncodeToString(e.other.key.PublicKey().Bytes()),
			hexID(e.other.name), e.other.ip)
		if err := e.own.dev.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
		if err := e.own.dev.Up(); err != nil {
			t.Fatal(err)
		}
	}
}

// ping sends pings from one end to the other until one arrives.
func ping(t *testing.T, from, to *wgEnd) {
	t.Helper()
	want := tuntest.Ping(to.ip, from.ip)
	deadline := time.Now().Add(3 * wait)
	for time.Now().Before(deadline) {
		from.tun.Outbound <- tuntest.Ping(to.ip, from.ip)
		select {
		case got := <-to.tun.Inbound:
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x, want the ping %x", got, want)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("no ping from %s reached %s", from.name, to.name)
}

func (e *wgEnd) get(t *testing.T, key string) string {
	t.Helper()
	s, err := e.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(s) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return v
		}
	}
	return ""
}

func TestWireGuardThroughARelay(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		f.add("A", "R", "B")
		f.dial("A", "R")
		f.dial("B", "R")
		f.route("R", "A", "A")
		f.route("R", "B", "B")
		a := f.wireguard("A", "10.9.0.1", peer("B", "R"))
		b := f.wireguard("B", "10.9.0.2", peer("A", "R"))
		pair(t, a, b)

		ping(t, a, b)
		ping(t, b, a)
		for _, e := range []*wgEnd{a, b} {
			// WireGuard reports a port only once its Bind opened one.
			if port := e.get(t, "listen_port"); port != "" {
				t.Fatalf("%s's WireGuard listens on port %s; it must have no socket", e.name, port)
			}
		}
		if got := a.get(t, "endpoint"); got != hexID("B") {
			t.Fatalf("A's WireGuard sees B at %q, want B's node id", got)
		}
		if r := f.node("R").Counters(); r.Forwarded < 4 || r.Delivered != 0 {
			t.Fatalf("relay counters %+v: it must only forward", r)
		}
	})
}

// Losing the first hop moves traffic to the next one; WireGuard's session
// with the peer carries on, without a new handshake.
func TestWireGuardSessionSurvivesAPathSwitch(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		f.add("A", "B", "R1", "R2")
		for _, end := range []string{"A", "B"} {
			for _, r := range []string{"R1", "R2"} {
				f.dial(end, r)
				f.route(r, end, end)
			}
		}
		a := f.wireguard("A", "10.9.0.1", peer("B", "R1", "R2"))
		b := f.wireguard("B", "10.9.0.2", peer("A", "R1", "R2"))
		pair(t, a, b)
		ping(t, a, b)
		ping(t, b, a)
		handshake := a.get(t, "last_handshake_time_nsec") + "/" + a.get(t, "last_handshake_time_sec")
		if hop, _ := a.bind.Current(id("B")); hop != id("R1") {
			t.Fatalf("A starts on %s, want R1", hop)
		}

		f.silence("A", "R1")
		f.silence("B", "R1")
		ping(t, a, b)
		ping(t, b, a)
		if hop, _ := a.bind.Current(id("B")); hop != id("R2") {
			t.Fatalf("A sends through %s, want R2", hop)
		}
		if hop, _ := b.bind.Current(id("A")); hop != id("R2") {
			t.Fatalf("B sends through %s, want R2", hop)
		}
		if now := a.get(t, "last_handshake_time_nsec") + "/" + a.get(t, "last_handshake_time_sec"); now != handshake {
			t.Fatalf("WireGuard handshook again (%s, was %s): the session didn't survive the switch", now, handshake)
		}
	})
}
