//go:build linux && !android

package supervisor_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// forgedSender is the sender address of the space's forged ARP: one that
// isn't the space's.
var forgedSender = netip.MustParseAddr("192.0.2.99")

// TestForgedARPIsDropped: a space sends ARP with a forged sender address
// toward its root end (a broadcast request for the root end, a gratuitous
// request and a unicast reply); the arp chain drops it, so the root
// namespace's neighbour table never learns the forged address. The
// negative control puts the chain on the ARP output hook, where it never
// matches, and the root learns it.
func TestForgedARPIsDropped(t *testing.T) {
	needsLab(t)
	// Reverse-path filtering would refuse the forged sender before the
	// root's ARP handling learned it, and hide the negative control.
	rootSysctls(t, "0", "net/ipv4/conf/all/rp_filter", "net/ipv4/conf/default/rp_filter")
	for _, onInput := range []bool{true, false} {
		t.Run(fmt.Sprintf("input=%v", onInput), func(t *testing.T) {
			opts := options(nil)
			if !onInput {
				opts = supervisor.WithArpOnOutput(opts)
			}
			space := netmap.NewSpaceID()
			s := start(t, opts, space)
			w, _ := info(s, space)
			before := nftDrops(t, "arp", supervisor.ArpTableName, "input")
			sendForgedARP(t, w.PID, w.Link, w.RootAddrs[0].Addr())

			if !onInput {
				eventually(t, 15*time.Second, "the root learns the forged sender with the chain on output", func() error {
					if !learned(t, w.Link) {
						return fmt.Errorf("no entry; root's neighbours on %s: %q", w.Link, neighbours(t, w.Link))
					}
					return nil
				})
				return
			}
			awaitNftDrops(t, "arp", supervisor.ArpTableName, "input", before, 30)
			if learned(t, w.Link) {
				t.Fatalf("the root learned the forged sender: %q", neighbours(t, w.Link))
			}
		})
	}
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// sendForgedARP sends, from inside the worker's network namespace, ARP with
// forgedSender as its sender toward rootAddr on the root end rootLink: a
// broadcast request for rootAddr, a gratuitous request and a reply to the
// root end's MAC, every 20 ms until the test ends.
func sendForgedARP(t *testing.T, pid int, rootLink string, rootAddr netip.Addr) {
	t.Helper()
	root, err := net.InterfaceByName(rootLink)
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	var ifi *net.Interface
	inWorker(t, pid, func() {
		if ifi, err = net.InterfaceByName(supervisor.SpaceInterface); err != nil {
			return
		}
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	zero := make(net.HardwareAddr, 6)
	type send struct {
		frame []byte
		to    *unix.SockaddrLinklayer
	}
	var sends []send
	for _, f := range []struct {
		dst net.HardwareAddr
		op  uint16
		tha net.HardwareAddr
		tpa netip.Addr
	}{
		{broadcastMAC, 1, zero, rootAddr},                   // request
		{broadcastMAC, 1, zero, forgedSender},               // gratuitous
		{root.HardwareAddr, 2, root.HardwareAddr, rootAddr}, // reply
	} {
		frame := make([]byte, 0, 42)
		frame = append(frame, f.dst...)
		frame = append(frame, ifi.HardwareAddr...)
		frame = binary.BigEndian.AppendUint16(frame, unix.ETH_P_ARP)
		frame = binary.BigEndian.AppendUint16(frame, 1)             // hardware: Ethernet
		frame = binary.BigEndian.AppendUint16(frame, unix.ETH_P_IP) // protocol: IPv4
		frame = append(frame, 6, 4)                                 // address lengths
		frame = binary.BigEndian.AppendUint16(frame, f.op)
		frame = append(frame, ifi.HardwareAddr...)
		frame = append(frame, forgedSender.AsSlice()...)
		frame = append(frame, f.tha...)
		frame = append(frame, f.tpa.AsSlice()...)
		to := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
		copy(to.Addr[:], f.dst)
		sends = append(sends, send{frame, to})
	}

	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			for _, s := range sends {
				if err := unix.Sendto(fd, s.frame, 0, s.to); err != nil {
					t.Errorf("sending forged ARP: %v", err)
					return
				}
			}
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		<-exited
		_ = unix.Close(fd)
	})
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// learned reports whether the root namespace has a neighbour entry for
// forgedSender on link, in any state.
func learned(t *testing.T, link string) bool {
	return strings.Contains(neighbours(t, link), forgedSender.String()+" ")
}

// neighbours is the root namespace's IPv4 neighbour table on link.
func neighbours(t *testing.T, link string) string {
	t.Helper()
	out, err := exec.Command("ip", "-4", "neigh", "show", "dev", link, "nud", "all").CombinedOutput()
	if err != nil {
		t.Fatalf("ip neigh show dev %s: %v: %s", link, err, out)
	}
	return string(out)
}
