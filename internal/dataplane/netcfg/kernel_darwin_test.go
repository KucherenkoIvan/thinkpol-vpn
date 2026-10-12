package netcfg

import (
	"testing"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The messages Apply writes read back as the routes they add, as the
// kernel would report them (KAME-embedded zones included).
func TestRouteMessagesRoundTrip(t *testing.T) {
	for _, r := range []kroute{
		{dst: pfx("10.0.0.0/8"), gw: ip("192.168.1.1"), flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | routeFlag},
		{dst: pfx("203.0.113.9/32"), gw: ip("192.168.1.1"), flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST | routeFlag},
		{dst: pfx("0.0.0.0/1"), link: 20, index: 20, flags: unix.RTF_UP | unix.RTF_STATIC | routeFlag},
		{dst: pfx("128.0.0.0/1"), link: 20, index: 20, flags: unix.RTF_UP | unix.RTF_STATIC | routeFlag},
		{dst: pfx("8000::/1"), gw: ip("::1"), flags: unix.RTF_UP | unix.RTF_REJECT | unix.RTF_GATEWAY | routeFlag},
		{dst: pfx("2001:db8::/32"), gw: ip("fe80::1"), gwZone: 11, index: 11, flags: unix.RTF_UP | unix.RTF_GATEWAY | routeFlag},
		{dst: pfx("fd12:3456:789a::/48"), link: 20, index: 20, flags: unix.RTF_UP | routeFlag},
		{dst: pfx("2001:db8::1/128"), gw: ip("fe80::1"), gwZone: 4, index: 4, flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST},
	} {
		b, err := routeMessage(unix.RTM_ADD, r, 7).Marshal()
		if err != nil {
			t.Fatalf("%v: %v", r, err)
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
		if err != nil || len(msgs) != 1 {
			t.Fatalf("%v: %v, %d messages", r, err, len(msgs))
		}
		rm := msgs[0].(*route.RouteMessage)
		got, ok := kernelRoute(rm)
		if !ok || got != r {
			t.Errorf("round trip of %v (%+v): %+v, %v", r, r, got, ok)
		}
		if rm.Type != unix.RTM_ADD || rm.Seq != 7 {
			t.Errorf("%v: type %d seq %d", r, rm.Type, rm.Seq)
		}
		if r.dst.Bits() == r.dst.Addr().BitLen() && rm.Addrs[unix.RTAX_NETMASK] != nil {
			t.Errorf("%v: a host route with a netmask", r)
		}
	}
}

func TestMaskBits(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		n    int
		okay bool
	}{
		{[]byte{255, 255, 255, 0}, 24, true},
		{[]byte{255, 240}, 12, true}, // cut short by the kernel
		{[]byte{128, 0, 0, 0}, 1, true},
		{[]byte{0, 0, 0, 0}, 0, true},
		{[]byte{}, 0, true},
		{[]byte{255, 0, 255, 0}, 0, false},
		{[]byte{254, 1}, 0, false},
		{[]byte{0x0f}, 0, false},
	} {
		n, ok := maskBits(tc.b)
		if ok != tc.okay || ok && n != tc.n {
			t.Errorf("%v: %d, %v; want %d, %v", tc.b, n, ok, tc.n, tc.okay)
		}
	}
	for _, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "100.64.0.0/10", "1.2.3.4/32", "::/0", "fd00::/7", "2001:db8::/33", "::1/128"} {
		m := maskOf(pfx(p))
		b := m.AsSlice()
		if n, ok := maskBits(b); !ok || n != pfx(p).Bits() {
			t.Errorf("mask of %s is %v: %d, %v", p, m, n, ok)
		}
	}
}

func TestRelevantRoutingEvents(t *testing.T) {
	rm := func(typ, flags int) route.Message { return &route.RouteMessage{Type: typ, Flags: flags} }
	for _, tc := range []struct {
		m    route.Message
		want bool
	}{
		{&route.InterfaceMessage{Type: unix.RTM_IFINFO}, true},
		{&route.InterfaceAddrMessage{Type: unix.RTM_NEWADDR}, true},
		{rm(unix.RTM_ADD, unix.RTF_UP|unix.RTF_GATEWAY), true},             // a default or a classless route
		{rm(unix.RTM_DELETE, unix.RTF_UP|unix.RTF_STATIC|routeFlag), true}, // ours, deleted
		{rm(unix.RTM_ADD, unix.RTF_UP|unix.RTF_STATIC|routeFlag), false},   // ours (or another owner's), added
		{rm(unix.RTM_ADD, unix.RTF_UP|unix.RTF_HOST|unix.RTF_WASCLONED), false},
		{rm(unix.RTM_DELETE, unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_IFSCOPE), false},
		{rm(unix.RTM_GET, unix.RTF_UP), false},
		{rm(unix.RTM_MISS, 0), false},
	} {
		if got := relevant(tc.m); got != tc.want {
			t.Errorf("%+v: %v", tc.m, got)
		}
	}
}

func TestTheIoctlArgumentsHaveTheKernelsSizes(t *testing.T) {
	// SIOCAIFADDR_IN6 as <netinet6/in6_var.h> defines it.
	if siocAIFADDRIn6 != 0x8080691a {
		t.Errorf("SIOCAIFADDR_IN6 %#x", siocAIFADDRIn6)
	}
	for name, tc := range map[string]struct{ req, size uintptr }{
		"SIOCAIFADDR":  {unix.SIOCAIFADDR, unsafe.Sizeof(ifaliasreq{})},
		"SIOCDIFADDR":  {unix.SIOCDIFADDR, unsafe.Sizeof(ifreqAddr{})},
		"SIOCSIFFLAGS": {unix.SIOCSIFFLAGS, unsafe.Sizeof(ifreqFlags{})},
		"SIOCGIFFLAGS": {unix.SIOCGIFFLAGS, unsafe.Sizeof(ifreqFlags{})},
	} {
		if got := tc.req >> 16 & 0x1fff; got != tc.size {
			t.Errorf("%s takes %d bytes, its argument has %d", name, got, tc.size)
		}
	}
}
