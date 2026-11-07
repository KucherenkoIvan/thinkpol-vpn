//go:build linux && !android

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// raLink is a link whose accept_ra 1 the dead supervisor set to 2 when
// it turned IPv6 forwarding on.
const raLink = "tplo-ra0"

// leftByADeadSupervisor puts in place what a supervisor killed while it
// served a space's egress leaves in the root namespace: the forwarding of
// both families it turned on (and raLink's accept_ra), with its record in
// run, its tables, and a space's veth. Next to them, what isn't the
// supervisor's: a link and an nftables table of someone else's. The
// returned sysctls are the ones the dead one wrote through, its hook
// disarmed.
func leftByADeadSupervisor(t *testing.T, run string) *hookSysctls {
	t.Helper()
	forwardingOff(t)
	setSysctl(t, forwardingKeys[1], "0")
	addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: raLink}})
	setSysctl(t, raKey, "1")
	sys := &hookSysctls{procSysFS: procSysFS{root: "/proc/sys"}}
	s := servingWithEgress(t, Options{RuntimeDir: run, sysctls: sys, Uplink: func() (egress.Uplink, error) {
		return egress.Uplink{Name: "lo", IPv4: true, IPv6: true}, nil
	}})
	// A Close that can't turn forwarding off leaves it as a kill does.
	sys.arm(refuseOff(forwardingKeys[:]...))
	_ = s.Close()
	sys.disarm()
	t.Cleanup(func() { _ = removeIsolation() })
	addLink(t, &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: LinkPrefix + "7"}, PeerName: "tplo-peer7"})
	addLink(t, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tplo-other0"}})
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	foreign := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tplo-foreign"}
	c.AddTable(foreign)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.DelTable(foreign); _ = c.Flush() })
	if got := sysctls(t, forwardingKeys[0], forwardingKeys[1], raKey); got != "1 1 2" || !hasRootTables(t) {
		t.Fatalf("the dead supervisor's leftovers: forwarding IPv4, IPv6, %s's accept_ra %s, tables there: %v", raLink, got, hasRootTables(t))
	}
	return sys
}

var raKey = "net/ipv6/conf/" + raLink + "/accept_ra"

// refuseOff refuses to turn off the forwarding switches keys.
func refuseOff(keys ...string) func(key, value string) error {
	return func(key, value string) error {
		if slices.Contains(keys, key) && value == "0" {
			return errors.New("refused")
		}
		return nil
	}
}

func addLink(t *testing.T, l netlink.Link) {
	t.Helper()
	if err := netlink.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(l) })
}

// setSysctl sets one of the root's sysctls for the test, and puts it back
// after.
func setSysctl(t *testing.T, key, value string) {
	t.Helper()
	was, err := realSysctl(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := (procSysFS{root: "/proc/sys"}).Write(key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = (procSysFS{root: "/proc/sys"}).Write(key, was) })
}

// sysctls are the root's values of keys, space-separated.
func sysctls(t *testing.T, keys ...string) string {
	t.Helper()
	var vs []string
	for _, k := range keys {
		v, err := realSysctl(k)
		if err != nil {
			t.Fatal(err)
		}
		vs = append(vs, v)
	}
	return strings.Join(vs, " ")
}

// tableEvents are the changes to the supervisor's tables made while
// during runs.
func tableEvents(t *testing.T, during func()) []string {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	mon := nftables.NewMonitor(nftables.WithMonitorObject(nftables.MonitorObjectTables), nftables.WithMonitorEventBuffer(64))
	events, err := c.AddMonitor(mon)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mon.Close() }()
	during()
	// A table of the test's own marks the end: the events arrive in order.
	end := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tplo-end"}
	c.AddTable(end)
	c.DelTable(end)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	var got []string
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-events:
			if !ok {
				t.Fatal("the monitor closed")
			}
			if e.Error != nil {
				t.Fatal(e.Error)
			}
			tb, ok := e.Data.(*nftables.Table)
			if !ok {
				continue
			}
			switch tb.Name {
			case end.Name:
				return got
			case TableName, ArpTableName:
				what := "added"
				if e.Type == nftables.MonitorEventTypeDelTable {
					what = "deleted"
				}
				got = append(got, what+" "+tb.Name)
			}
		case <-timeout:
			t.Fatalf("no end mark; so far: %q", got)
		}
	}
}

func linkThere(t *testing.T, name string) bool {
	t.Helper()
	_, err := netlink.LinkByName(name)
	var nf netlink.LinkNotFoundError
	if err != nil && !errors.As(err, &nf) {
		t.Fatal(err)
	}
	return err == nil
}

func foreignTableThere(t *testing.T) bool {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(ts, func(tb *nftables.Table) bool { return tb.Name == "tplo-foreign" })
}

// ClearLeftovers undoes what a dead supervisor left, and only that, and
// says what it undid.
func TestClearLeftoversUndoesADeadSupervisors(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	run := t.TempDir()
	leftByADeadSupervisor(t, run)
	undone, err := ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: run})
	if err != nil {
		t.Fatal(err)
	}
	v := sysctls(t, forwardingKeys[0], forwardingKeys[1], raKey)
	_, recErr := os.Stat(filepath.Join(run, forwardingFile))
	if v != "0 0 1" || hasRootTables(t) || linkThere(t, LinkPrefix+"7") || !errors.Is(recErr, os.ErrNotExist) {
		t.Fatalf("left: forwarding IPv4, IPv6, %s's accept_ra %s, tables %v, the space's link %v, record %v", raLink, v, hasRootTables(t), linkThere(t, LinkPrefix+"7"), recErr)
	}
	if !linkThere(t, "tplo-other0") || !foreignTableThere(t) {
		t.Fatal("removed what isn't the supervisor's")
	}
	said := strings.Join(undone, "\n")
	for _, want := range []string{LinkPrefix + "7", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", TableName, ArpTableName} {
		if !strings.Contains(said, want) {
			t.Errorf("%s isn't reported as undone:\n%s", want, said)
		}
	}
	// Nothing left: nothing to say, and nothing asked of nftables (a
	// kernel without nf_tables for ARP would refuse it).
	var again []string
	if events := tableEvents(t, func() { again, err = ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: run}) }); len(events) != 0 {
		t.Errorf("with no table of its own there, it changed: %q", events)
	}
	if err != nil || len(again) != 0 {
		t.Fatalf("again: %q, %v", again, err)
	}
}

// A live supervisor's role, links, tables and forwarding are never
// taken; a record that can't be read keeps the tables confining the
// forwarding it may name.
func TestClearLeftoversLeavesWhatItCantProveDead(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	t.Run("a live supervisor", func(t *testing.T) {
		forwardingOff(t)
		s := servingWithEgress(t, Options{RuntimeDir: t.TempDir()})
		defer func() { _ = s.Close() }()
		if _, err := ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: t.TempDir()}); !errors.Is(err, netcfg.ErrBusy) {
			t.Fatalf("got %v, want netcfg.ErrBusy", err)
		}
		if v, _ := realSysctl(forwardingKeys[0]); v != "1" || !hasRootTables(t) {
			t.Fatalf("the live supervisor's: forwarding %s, tables there: %v", v, hasRootTables(t))
		}
	})
	t.Run("forwarding it can't turn off", func(t *testing.T) {
		run := t.TempDir()
		sys := leftByADeadSupervisor(t, run)
		sys.arm(refuseOff(forwardingKeys[0]))
		defer sys.disarm()
		_, err := ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: run, sysctls: sys})
		if v, _ := realSysctl(forwardingKeys[0]); v != "1" || !hasRootTables(t) {
			t.Fatalf("the tables went with the forwarding they confine still on: forwarding %s, tables there: %v", v, hasRootTables(t))
		}
		if err == nil || !strings.Contains(err.Error(), "IPv4 (net.ipv4.ip_forward) forwarding still on") {
			t.Fatalf("got %v, want IPv4 forwarding reported still on", err)
		}
	})
	t.Run("an unreadable record", func(t *testing.T) {
		run := t.TempDir()
		leftByADeadSupervisor(t, run)
		if err := os.WriteFile(filepath.Join(run, forwardingFile), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: run})
		if !hasRootTables(t) {
			t.Fatal("the tables went with the forwarding they confine still on")
		}
		if err == nil {
			t.Fatal("no error for a record it can't read")
		}
	})
}
