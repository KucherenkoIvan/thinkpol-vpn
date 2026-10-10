package udp

import (
	"context"
	"flag"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// Ports the lab's shaping capture (lab/shaping_test.go) tells apart.
const (
	labUnshapedPort = 4500
	labShapedPort   = 4501
	labRepeats      = 3
)

var labTarget = flag.String("lab-target", "", "IP address TestLabSendShaped sends to (set by lab/shaping_test.go)")

// TestLabSendShaped runs in a lab node for lab/shaping_test.go, which
// captures at the router: the WireGuard-like packets go out unshaped to one
// port and padded to labBuckets to the other. The far end only drops them.
func TestLabSendShaped(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" || *labTarget == "" {
		t.Skip("needs the lab and -lab-target")
	}
	ip, err := netip.ParseAddr(*labTarget)
	if err != nil {
		t.Fatal(err)
	}
	tr := New(Options{})
	secret := transporttest.SymmetricPeer().Credential
	for port, s := range map[uint16]transport.Shaping{labUnshapedPort: {}, labShapedPort: labBuckets} {
		l, err := tr.Dial(context.Background(), netip.AddrPortFrom(ip, port).String(), transport.DialConfig{Credential: secret, Shaping: s})
		if err != nil {
			t.Fatal(err)
		}
		for range labRepeats {
			for _, size := range wireguardLikeSizes() {
				if err := l.WritePacket(make([]byte, size)); err != nil {
					t.Fatal(err)
				}
				time.Sleep(200 * time.Microsecond) // the capture, not the network, is what's measured
			}
		}
		st := l.(*dialLink).Sent()
		t.Logf("port %d: %d packets, %d padding bytes, overhead %.1f%%", port, st.Packets, st.PaddingBytes, 100*st.Overhead())
		_ = l.Close()
	}
}
