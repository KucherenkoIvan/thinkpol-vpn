//go:build linux && !android

package supervisor_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// forgedSender is the sender address of the space's forged ARP: one that
// isn't the space's.
var forgedSender = netip.MustParseAddr("192.0.2.99")

// TestForgedARPIsDropped: a space broadcasts ARP requests for its root end
// with a forged sender address; the arp chain drops them, so the root
// namespace's neighbour table never learns the forged address. The
// negative control puts the chain back on the ARP output hook, where it
// never matched, and the root learns it.
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
			before := arpDropped(t)
			stop := sendForgedARP(t, w.PID, w.RootAddrs[0].Addr())
			defer stop()

			if !onInput {
				eventually(t, 15*time.Second, "the root learns the forged sender with the chain on output", func() error {
					if !learned(t, w.Link) {
						return fmt.Errorf("no entry; root's neighbours on %s: %q", w.Link, neighbours(t, w.Link))
					}
					return nil
				})
				return
			}
			eventually(t, 15*time.Second, "the arp chain drops the forged requests", func() error {
				if got := arpDropped(t); got < before+10 {
					return fmt.Errorf("%d drops so far", got-before)
				}
				return nil
			})
			if learned(t, w.Link) {
				t.Fatalf("the root learned the forged sender: %q", neighbours(t, w.Link))
			}
		})
	}
}

// sendForgedARP broadcasts, from inside the worker's network namespace, an
// ARP request for target with forgedSender as its sender, every 20 ms until
// stop is called.
func sendForgedARP(t *testing.T, pid int, target netip.Addr) (stop func()) {
	t.Helper()
	var fd int
	var ifi *net.Interface
	err := nsthread.Do(func() error {
		ns, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil {
			return err
		}
		defer func() { _ = ns.Close() }()
		if err := netns.Set(ns); err != nil {
			return err
		}
		if ifi, err = net.InterfaceByName(supervisor.SpaceInterface); err != nil {
			return err
		}
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 0, 42)
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	frame = append(frame, ifi.HardwareAddr...)
	frame = binary.BigEndian.AppendUint16(frame, unix.ETH_P_ARP)
	frame = binary.BigEndian.AppendUint16(frame, 1)             // hardware: Ethernet
	frame = binary.BigEndian.AppendUint16(frame, unix.ETH_P_IP) // protocol: IPv4
	frame = append(frame, 6, 4)                                 // address lengths
	frame = binary.BigEndian.AppendUint16(frame, 1)             // operation: request
	frame = append(frame, ifi.HardwareAddr...)
	frame = append(frame, forgedSender.AsSlice()...)
	frame = append(frame, make([]byte, 6)...)
	frame = append(frame, target.AsSlice()...)
	to := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			_ = unix.Sendto(fd, frame, 0, to)
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	return func() {
		close(done)
		<-exited
		_ = unix.Close(fd)
	}
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

// arpDropped is the drop counter of the supervisor's arp chain.
func arpDropped(t *testing.T) uint64 {
	t.Helper()
	out, err := exec.Command("nft", "list", "chain", "arp", supervisor.ArpTableName, "input").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list chain arp input: %v: %s", err, out)
	}
	var n uint64
	for _, m := range counterRE.FindAllStringSubmatch(string(out), -1) {
		v, _ := strconv.ParseUint(m[1], 10, 64)
		n += v
	}
	return n
}
