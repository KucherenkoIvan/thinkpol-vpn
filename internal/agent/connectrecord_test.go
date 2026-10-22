//go:build linux || darwin

package agent

import (
	"context"
	"path/filepath"
	"testing"
)

// A device's restart in the same boot (a crash and its service's restart)
// comes back as the member last asked through the local API, whatever the
// configuration says; a boot starts as configured (connect-on-boot), and
// without a local API the configuration always decides.
func TestARestartInTheSameBootKeepsTheLastConnectRequest(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	ctx := context.Background()
	dir := filepath.Join(tempDir(t), "thinkpol")
	inBoot := func(boot string) deviceOpt {
		return deviceOpt{prepare: func(_ *Config, p *Platform) {
			p.ConnectRecord = fileConnectRecord{dir: dir, boot: bootOf(boot)}
		}}
	}
	withoutAPI := deviceOpt{prepare: func(c *Config, _ *Platform) { c.APISocket = "" }}
	restart := func(b *deviceNode) {
		t.Helper()
		b.stop()
		if err := <-b.done; err != nil {
			t.Fatal(err)
		}
		b.done <- nil // for the cleanup
	}

	// Installed as a service: connect-on-boot off. The member connects.
	b := startDevice(t, s, reg, false, inBoot("boot-1"))
	b.connection(t, Disconnected)
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// Restarted in the same boot: connected again, though configured off.
	b = startDevice(t, s, reg, false, inBoot("boot-1"))
	b.connection(t, Connected)
	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	restart(b)

	// An explicit disconnect isn't undone by a configuration that
	// connects.
	b = startDevice(t, s, reg, true, inBoot("boot-1"))
	b.connection(t, Disconnected)
	restart(b)

	// Without a local API nothing could have asked: the configuration.
	b = startDevice(t, s, reg, true, inBoot("boot-1"), withoutAPI)
	b.connection(t, Connected)
	restart(b)

	// The next boot starts as configured, either way.
	b = startDevice(t, s, reg, false, inBoot("boot-2"))
	b.connection(t, Disconnected)
	restart(b)
	b = startDevice(t, s, reg, true, inBoot("boot-2"))
	b.connection(t, Connected)
}

// A request taken while the device is out of its space is recorded too:
// it is what a restart comes back to.
func TestARequestWhileRemovedIsRecorded(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	rec := &memConnectRecord{}
	b := startDevice(t, s, reg, false, deviceOpt{prepare: func(c *Config, p *Platform) {
		writeFile(t, filepath.Join(c.StateDir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
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
