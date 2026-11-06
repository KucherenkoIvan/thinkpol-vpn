//go:build linux || darwin

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Under the service (-service) a device comes back, in the
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
	// The service, the device's connect-on-boot on or off ("": run by
	// hand); startDevice's connect argument (-connect) is given the other
	// way, to show it isn't read.
	service := func(boot, onBoot string) deviceOpt {
		return deviceOpt{prepare: func(c *Config, p *Platform) {
			c.Service = onBoot != ""
			if onBoot != "" {
				writeFile(t, filepath.Join(c.StateDir, DeviceFile), []byte(`{"connect_on_boot": `+strconv.FormatBool(onBoot == "on")+"}\n"), 0o600)
			}
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
	b := startDevice(t, s, reg, true, service("boot-1", "off"))
	b.connection(t, Disconnected)
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// Restarted in the same boot: connected again, though configured off.
	b = startDevice(t, s, reg, false, service("boot-1", "off"))
	b.connection(t, Connected)
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// An explicit disconnect isn't undone by connect-on-boot turned on.
	b = startDevice(t, s, reg, true, service("boot-1", "on"))
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
	b = startDevice(t, s, reg, true, service("boot-1", "on"))
	b.connection(t, Disconnected)
	restart(b)

	// The next boot starts as connect-on-boot says, and its first start
	// records that: a restart in the boot keeps it, whatever
	// connect-on-boot says by then.
	b = startDevice(t, s, reg, false, service("boot-2", "on"))
	b.connection(t, Connected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-2", "off"))
	b.connection(t, Connected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-3", "off"))
	b.connection(t, Disconnected)
	restart(b)
	b = startDevice(t, s, reg, false, service("boot-3", "on"))
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
		c.Service = true
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

func TestTheServiceNeedsTheAPI(t *testing.T) {
	for _, tc := range []struct {
		service bool
		socket  string
		ok      bool
	}{
		{false, "", true}, // -connect alone, as by hand (a device that connects)
		{true, "/run/thinkpol-api/api.sock", true},
		{true, "", false},
	} {
		cfg := testConfig("/var/lib/thinkpol")
		cfg.Service, cfg.APISocket = tc.service, tc.socket
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("service %v, socket %q: %v", tc.service, tc.socket, err)
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
		c.Service = true
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

// Connect-on-boot is the member's toggle: set through the node (the local
// API's SetConnectOnBoot), stored in the device file 0600, shown in the
// status, and read at the next boot's first start, not before. A server
// refuses it.
func TestConnectOnBootIsTheDevicesToggle(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	dir := filepath.Join(tempDir(t), "thinkpol")
	var state string
	service := func(boot string) deviceOpt {
		return deviceOpt{prepare: func(c *Config, p *Platform) {
			if state == "" {
				state = c.StateDir
			}
			c.StateDir, c.Service = state, true
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

	// No device file: off. Turned on, it is stored and shown, and this
	// boot's device stays as it is.
	b := startDevice(t, s, reg, true, service("boot-1"))
	b.connection(t, Disconnected)
	if b.node.Status().ConnectOnBoot {
		t.Fatal("connect-on-boot on without a device file")
	}
	if err := b.node.SetConnectOnBoot(true); err != nil {
		t.Fatal(err)
	}
	if !b.node.Status().ConnectOnBoot {
		t.Fatal("the status doesn't show connect-on-boot on")
	}
	file := filepath.Join(state, DeviceFile)
	if fi, err := os.Lstat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the device file: %v %v", fi, err)
	}
	b.connection(t, Disconnected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-1"))
	b.connection(t, Disconnected) // the same boot: as it was left

	// The next boot connects; turned off, the one after stays down.
	restart(b)
	b = startDevice(t, s, reg, false, service("boot-2"))
	b.connection(t, Connected)
	if err := b.node.SetConnectOnBoot(false); err != nil {
		t.Fatal(err)
	}
	b.connection(t, Connected)
	restart(b)
	b = startDevice(t, s, reg, true, service("boot-3"))
	b.connection(t, Disconnected)
	if b.node.Status().ConnectOnBoot {
		t.Fatal("connect-on-boot still on")
	}

	// A server serves whenever it runs.
	a, err := Prepare(testConfig(s.stateDir(t, s.a, 1)), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetConnectOnBoot(true); !errors.Is(err, ErrServerMode) {
		t.Fatalf("a server: %v", err)
	}
}
