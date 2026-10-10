package lab

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestStandardTopologyIsValid(t *testing.T) {
	if err := Standard().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := GoTestTopology().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTopologyValidateRejects(t *testing.T) {
	base := Topology{Networks: []Network{{Name: "net"}}}
	for name, topo := range map[string]Topology{
		"no nodes":          base,
		"bad name":          base.With(NodeSpec{Name: "Device_A", Networks: []string{"net"}}),
		"no network":        base.With(NodeSpec{Name: "a"}),
		"unknown network":   base.With(NodeSpec{Name: "a", Networks: []string{"other"}}),
		"unknown gateway":   base.With(NodeSpec{Name: "a", Networks: []string{"net"}, Gateway: "gw"}),
		"duplicate network": base.WithNetworks(Network{Name: "net"}).With(NodeSpec{Name: "a", Networks: []string{"net"}}),
		"gateway elsewhere": base.WithNetworks(Network{Name: "other"}).With(
			NodeSpec{Name: "a", Networks: []string{"net"}, Gateway: "gw"},
			NodeSpec{Name: "gw", Networks: []string{"other"}},
		),
	} {
		if err := topo.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWithReplacesAndAddsWithoutTouchingTheOriginal(t *testing.T) {
	std := Standard()
	topo := std.With(
		NodeSpec{Name: Server1, Networks: []string{NetServers}, Command: []string{"thinkpol", "up"}},
		NodeSpec{Name: "server-3", Networks: []string{NetServers}, Gateway: Router},
	)
	if len(topo.Nodes) != len(std.Nodes)+1 {
		t.Fatalf("%d nodes", len(topo.Nodes))
	}
	if got := topo.Nodes[topo.nodeIndex(Server1)].Command; len(got) != 2 {
		t.Errorf("server-1 not replaced: %v", got)
	}
	if std.Nodes[std.nodeIndex(Server1)].Command != nil {
		t.Error("With changed the original topology")
	}
}

func TestRenderComposeLeavesNamesAndSubnetsToDocker(t *testing.T) {
	out, err := renderCompose("proj-a", Standard(), "thinkpol-lab:test", "/checkout")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixed := range []string{"container_name", "ipam", "subnet", "network_mode"} {
		if bytes.Contains(out, []byte(fixed)) {
			t.Errorf("compose file sets %s", fixed)
		}
	}
	var f composeFile
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if f.Name != "proj-a" || len(f.Services) != len(Standard().Nodes) {
		t.Fatalf("project %q with %d services", f.Name, len(f.Services))
	}
	for name, net := range f.Networks {
		if !net.EnableIPv6 {
			t.Errorf("network %s without IPv6", name)
		}
	}
	router := f.Services[Router]
	if router.Sysctls["net.ipv4.ip_forward"] != "1" || router.Sysctls["net.ipv6.conf.all.forwarding"] != "1" {
		t.Errorf("router doesn't forward: %v", router.Sysctls)
	}
	if !router.Privileged || router.Devices[0] != "/dev/net/tun" {
		t.Error("router is not a privileged node with a TUN device")
	}
	if router.Volumes[0] != "/checkout/lab/bin:"+BinDir+":ro" {
		t.Errorf("binaries mounted as %s", router.Volumes[0])
	}
	if _, ok := f.Services[DeviceA].Networks[NetServers]; ok {
		t.Error("device-a is on the servers network")
	}
}

func TestProjectNames(t *testing.T) {
	t.Setenv(ProjectEnv, "")
	a := CheckoutProject("/x/worktrees/tp-002-lab-harness")
	b := CheckoutProject("/y/worktrees/tp-002-lab-harness")
	if a == b || !strings.HasPrefix(a, "tp-002-lab-harness-") {
		t.Errorf("checkout projects %q, %q", a, b)
	}
	p1 := testProject(a, "/x/lab", "TestSmoke/IPv4 over UDP")
	p2 := testProject(a, "/x/other", "TestSmoke/IPv4 over UDP")
	if p1 == p2 || !belongsTo(p1, a) || belongsTo(p1, b) {
		t.Errorf("test projects %q, %q", p1, p2)
	}
	if belongsTo(a+"x", a) {
		t.Error("a checkout whose name extends another's belongs to it")
	}
	for _, p := range []string{a, p1} {
		if slug(p, 100) != p {
			t.Errorf("%q is not a valid Compose project name", p)
		}
	}
	t.Setenv(ProjectEnv, "Second Run")
	if got := CheckoutProject("/x/worktrees/tp-002-lab-harness"); got != "second-run" {
		t.Errorf("override gave %q", got)
	}
}

func TestPcapStreamDecodesSLL2(t *testing.T) {
	src4, dst4 := netip.MustParseAddr("172.20.0.3"), netip.MustParseAddr("172.21.0.2")
	src6, dst6 := netip.MustParseAddr("fd00::3"), netip.MustParseAddr("fd00:1::2")
	payload := []byte("hello lab\n")

	var stream bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(hdr[20:], linkSLL2)
	stream.Write(hdr)
	record := func(ifindex uint32, outgoing bool, ip []byte) {
		sll := make([]byte, 20)
		binary.BigEndian.PutUint32(sll[4:], ifindex)
		if outgoing {
			sll[10] = 4
		}
		frame := append(sll, ip...)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec, 1700000000)
		binary.LittleEndian.PutUint32(rec[4:], 5)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
		stream.Write(rec)
		stream.Write(frame)
	}
	record(7, false, udp4(src4, dst4, 40000, 9999, payload))
	record(9, true, udp6(src6, dst6, 40000, 9999, payload))
	stream.Write([]byte{1, 2, 3}) // a stream cut mid-record ends cleanly

	r, err := newPcapReader(&stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []Packet{
		{Ifindex: 7, Src: src4, Dst: dst4},
		{Ifindex: 9, Outgoing: true, Src: src6, Dst: dst6},
	} {
		got, err := r.next()
		if err != nil {
			t.Fatal(err)
		}
		if got.Ifindex != want.Ifindex || got.Outgoing != want.Outgoing || got.Src != want.Src || got.Dst != want.Dst ||
			got.Proto != ProtoUDP || got.SrcPort != 40000 || got.DstPort != 9999 || !bytes.Equal(got.Payload, payload) {
			t.Errorf("decoded %+v", got)
		}
		if !got.Time.Equal(time.Unix(1700000000, 5000)) {
			t.Errorf("time %v", got.Time)
		}
	}
	if _, err := r.next(); err != io.EOF {
		t.Errorf("after the last record: %v", err)
	}
}

func udp4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20+8+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8], ip[9] = 64, ProtoUDP
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	udp(ip[20:], sport, dport, payload)
	return ip
}

func udp6(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 40+8+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+len(payload)))
	ip[6], ip[7] = ProtoUDP, 64
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())
	udp(ip[40:], sport, dport, payload)
	return ip
}

func udp(b []byte, sport, dport uint16, payload []byte) {
	binary.BigEndian.PutUint16(b, sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	copy(b[8:], payload)
}
