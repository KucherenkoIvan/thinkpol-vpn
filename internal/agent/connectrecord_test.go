//go:build linux || darwin

package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// Under the service (connect-on-boot set) a device comes back, in the
// same boot (a crash and its service's restart), as the member left it
// through the local API, or as the boot's first start came up, whatever
// connect-on-boot says by then; a boot starts as connect-on-boot says.
// Run by hand, -connect decides every start and nothing is recorded.
func TestARestartInTheSameBootKeepsTheLastConnectRequest(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	ctx := context.Background()
	dir := filepath.Join(tempDir(t), "thinkpol")
	// The service, connect-on-boot on or off; startDevice's connect
	// argument (-connect) is given the other way, to show it isn't read.
	service := func(boot, onBoot string) deviceOpt {
		return deviceOpt{prepare: func(c *Config, p *Platform) {
			c.ConnectOnBoot = onBoot
			p.ConnectRecord = fileConnectRecord{dir: dir, boot: bootOf(boot)}
		}}
	}
	restart := func(b *deviceNode) {
		t.Helper()
		b.stop()
		if err := <-b.done; err != nil {
			t.Fatal(err)
		}
		b.done <- nil // for the cleanup
	}

	// Installed as a service: connect-on-boot off. The member connects.
	b := startDevice(t, s, reg, true, service("boot-1", ConnectOnBootOff))
	b.connection(t, Disconnected)
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// Restarted in the same boot: connected again, though configured off.
	b = startDevice(t, s, reg, false, service("boot-1", ConnectOnBootOff))
	b.connection(t, Connected)
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// An explicit disconnect isn't undone by connect-on-boot turned on.
	b = startDevice(t, s, reg, true, service("boot-1", ConnectOnBootOn))
	b.connection(t, Disconnected)
	restart(b)

	// Run by hand: -connect decides, and nothing is recorded (the
	// service's start below still finds the disconnect).
	b = startDevice(t, s, reg, true, service("boot-1", ""))
	b.connection(t, Connected)
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-1", ConnectOnBootOn))
	b.connection(t, Disconnected)
	restart(b)

	// The next boot starts as connect-on-boot says, and its first start
	// records that: a restart in the boot keeps it, whatever
	// connect-on-boot says by then.
	b = startDevice(t, s, reg, false, service("boot-2", ConnectOnBootOn))
	b.connection(t, Connected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-2", ConnectOnBootOff))
	b.connection(t, Connected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-3", ConnectOnBootOff))
	b.connection(t, Disconnected)
	restart(b)
	b = startDevice(t, s, reg, false, service("boot-3", ConnectOnBootOn))
	b.connection(t, Disconnected)
}

// A Connect that fails leaves the device down, and the record says so: a
// restart in the boot doesn't connect on a request that never took.
func TestAFailedConnectIsRecordedDown(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	rec := &memConnectRecord{}
	b := startDevice(t, s, reg, true, deviceOpt{prepare: func(c *Config, p *Platform) {
		c.ConnectOnBoot = ConnectOnBootOff
		p.ConnectRecord = rec
	}})
	b.connection(t, Disconnected)
	b.failTUN <- struct{}{}
	var se *StartError
	if err := b.node.Connect(context.Background()); !errors.As(err, &se) {
		t.Fatalf("got %v, want a StartError", err)
	}
	b.connection(t, Disconnected)
	if c, ok, _ := rec.Load(); !ok || c {
		t.Fatalf("after a failed Connect the record says connect %v (recorded %v)", c, ok)
	}
}

func TestConnectOnBootIsOnOffOrNothingAndNeedsTheAPI(t *testing.T) {
	for _, tc := range []struct {
		onBoot, socket string
		ok             bool
	}{
		{"", "", true}, // -connect alone, as by hand (a device that connects)
		{ConnectOnBootOn, "/run/thinkpol-api/api.sock", true},
		{ConnectOnBootOff, "/run/thinkpol-api/api.sock", true},
		{"yes", "/run/thinkpol-api/api.sock", false},
		{ConnectOnBootOff, "", false},
	} {
		cfg := testConfig("/var/lib/thinkpol")
		cfg.ConnectOnBoot, cfg.APISocket = tc.onBoot, tc.socket
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("connect-on-boot %q, socket %q: %v", tc.onBoot, tc.socket, err)
		}
	}
}

// A request taken while the device is out of its space is recorded too:
// it is what a restart comes back to.
func TestARequestWhileRemovedIsRecorded(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	rec := &memConnectRecord{}
	b := startDevice(t, s, reg, false, deviceOpt{prepare: func(c *Config, p *Platform) {
		writeFile(t, filepath.Join(c.StateDir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
		c.ConnectOnBoot = ConnectOnBootOff
		p.ConnectRecord = rec
	}})
	if err := b.node.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, ok, _ := rec.Load(); !ok || !c {
		t.Fatalf("after a Connect while removed: %v %v", c, ok)
	}
	if err := b.node.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, ok, _ := rec.Load(); !ok || c {
		t.Fatalf("after a Disconnect while removed: %v %v", c, ok)
	}
}
