package packettest

import (
	"bytes"
	"net/netip"
	"testing"
)

// A packet's checksums verify: summing a checked range, checksum included,
// gives all ones.
func TestChecksumsVerify(t *testing.T) {
	for _, c := range []struct{ src, dst string }{{"100.64.0.1", "100.64.0.2"}, {"fd00::1", "fd00::2"}} {
		src, dst := netip.MustParseAddr(c.src), netip.MustParseAddr(c.dst)
		for _, pkt := range [][]byte{
			Echo(src, dst, 7, 9, []byte("hello")),
			UDPDatagram(netip.AddrPortFrom(src, 1000), netip.AddrPortFrom(dst, 2000), []byte("odd")),
		} {
			p, ok := Parse(pkt)
			if !ok || p.Src != src || p.Dst != dst {
				t.Fatalf("parse %x: %+v %v", pkt, p, ok)
			}
			var pseudo []byte
			if src.Is4() {
				if sum(0, pkt[:20]) != 0xffff {
					t.Fatalf("IPv4 header checksum of %x", pkt)
				}
				if p.Proto == UDP {
					s, d := src.As4(), dst.As4()
					pseudo = append(append(s[:], d[:]...), 0, UDP, 0, byte(len(p.Payload)))
				}
			} else {
				s, d := src.As16(), dst.As16()
				pseudo = append(append(s[:], d[:]...), 0, 0, 0, byte(len(p.Payload)), 0, 0, 0, byte(p.Proto))
			}
			if got := sum(uint32(sum(0, pseudo)), p.Payload); got != 0xffff {
				t.Fatalf("%s checksum of %x sums to %#x", c.dst, pkt, got)
			}
		}
	}
}

func TestReplyAnswersEchoRequests(t *testing.T) {
	for _, c := range []struct{ src, dst string }{{"100.64.0.1", "100.64.0.2"}, {"fd00::1", "fd00::2"}} {
		src, dst := netip.MustParseAddr(c.src), netip.MustParseAddr(c.dst)
		reply, ok := Reply(Echo(src, dst, 7, 9, []byte("data")))
		if !ok {
			t.Fatal("no reply")
		}
		p, _ := Parse(reply)
		if p.Src != dst || p.Dst != src || !IsEchoReply(p, 7, 9) || !bytes.Equal(p.Payload[8:], []byte("data")) {
			t.Fatalf("reply %+v", p)
		}
		if _, ok := Reply(reply); ok {
			t.Fatal("a reply was answered")
		}
	}
}
