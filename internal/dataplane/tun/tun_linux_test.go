//go:build linux && !android

package tun_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread/nsthreadtest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
)

func needsLab(t *testing.T) {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
}

func throwawayNetns(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	ns := "tuntest-" + hex.EncodeToString(b)
	ip(t, "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	return ns
}

func ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// A TUN created in another namespace lives there only, and moves packets
// both ways with the headroom the router and WireGuard leave.
func TestCreateInNamespace(t *testing.T) {
	needsLab(t)
	ns := throwawayNetns(t)

	dev, err := tun.CreateInNamespace("/run/netns/"+ns, tun.DefaultName, 1400)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = dev.Close()
		}
	})
	go func() {
		for range dev.Events() {
		}
	}()
	if out := ip(t, "-n", ns, "-o", "link", "show", "dev", tun.DefaultName); !strings.Contains(out, "mtu 1400") {
		t.Fatalf("TUN in the namespace: %s", out)
	}
	if err := exec.Command("ip", "link", "show", "dev", tun.DefaultName).Run(); err == nil {
		t.Fatal("the TUN is in this namespace too")
	}

	ip(t, "-n", ns, "addr", "add", "100.64.0.1/24", "dev", tun.DefaultName)
	ip(t, "-n", ns, "link", "set", "dev", tun.DefaultName, "up")
	const offset = 16
	own, peer := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	req := append(make([]byte, offset), packettest.Echo(peer, own, 7, 1, []byte("hello"))...)
	if _, err := dev.Write([][]byte{req}, offset); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset+65535)
	}
	sizes := make([]int, len(bufs))
	got := make(chan bool, 1)
	go func() {
		for {
			n, err := dev.Read(bufs, sizes, offset)
			if err != nil {
				got <- false
				return
			}
			for i := range n {
				if p, ok := packettest.Parse(bufs[i][offset : offset+sizes[i]]); ok && packettest.IsEchoReply(p, 7, 1) && p.Dst == peer {
					got <- true
					return
				}
			}
		}
	}()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("read failed before the reply")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the namespace's kernel didn't answer through the TUN")
	}

	closed = true
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "-n", ns, "link", "show", "dev", tun.DefaultName).Run(); err == nil {
		t.Fatal("the TUN outlived Close")
	}
}

// Creating TUNs in another namespace many times, one after another and then
// at once, leaves every thread of the process, the main one included, in its
// own namespace.
func TestCreateInNamespaceLeavesNoThreadBehind(t *testing.T) {
	needsLab(t)
	// A fresh name each time: the kernel may still hold the last one for a
	// moment after Close. Close's own error isn't checked: wireguard-go's
	// Close races its netlink listener and can report a broken pipe, with
	// the device gone all the same.
	var made atomic.Int32
	createAndClose := func(ns string) error {
		dev, err := tun.CreateInNamespace("/run/netns/"+ns, fmt.Sprintf("tpleak%d", made.Add(1)), 1400)
		if err != nil {
			return err
		}
		go func() {
			for range dev.Events() {
			}
		}()
		_ = dev.Close()
		return nil
	}
	ns := throwawayNetns(t)
	for range 100 {
		if err := createAndClose(ns); err != nil {
			t.Fatal(err)
		}
	}
	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		ns := throwawayNetns(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 / workers {
				if err := createAndClose(ns); err != nil {
					errs <- fmt.Errorf("worker %d: %w", w, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	nsthreadtest.CheckThreadsHome(t)
}
