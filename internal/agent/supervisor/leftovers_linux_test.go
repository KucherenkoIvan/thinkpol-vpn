//go:build linux && !android

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// leftByADeadSupervisor puts in place what a supervisor killed while it
// served a space's egress leaves in the root namespace: the forwarding it
// turned on, with its record in run, its tables, and a space's veth.
// Next to them, what isn't the supervisor's: a link and an nftables table
// of someone else's.
func leftByADeadSupervisor(t *testing.T, run string) {
	t.Helper()
	forwardingOff(t)
	sys := &hookSysctls{procSysFS: procSysFS{root: "/proc/sys"}}
	s := servingWithEgress(t, Options{RuntimeDir: run, sysctls: sys})
	// A Close that can't turn forwarding off leaves it as a kill does.
	sys.arm(func(key, value string) error {
		if key == forwardingKeys[0] && value == "0" {
			return errors.New("refused")
		}
		return nil
	})
	_ = s.Close()
	sys.disarm()
	t.Cleanup(func() { _ = removeIsolation() })
	for _, l := range []netlink.Link{
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: LinkPrefix + "7"}, PeerName: "tplo-peer7"},
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tplo-other0"}},
	} {
		if err := netlink.LinkAdd(l); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(l) })
	}
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
	if v, _ := realSysctl(forwardingKeys[0]); v != "1" || !hasRootTables(t) {
		t.Fatalf("the dead supervisor's leftovers: forwarding %s, tables there: %v", v, hasRootTables(t))
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
	v, _ := realSysctl(forwardingKeys[0])
	_, recErr := os.Stat(filepath.Join(run, forwardingFile))
	if v != "0" || hasRootTables(t) || linkThere(t, LinkPrefix+"7") || !errors.Is(recErr, os.ErrNotExist) {
		t.Fatalf("left: forwarding %s, tables %v, the space's link %v, record %v", v, hasRootTables(t), linkThere(t, LinkPrefix+"7"), recErr)
	}
	if !linkThere(t, "tplo-other0") || !foreignTableThere(t) {
		t.Fatal("removed what isn't the supervisor's")
	}
	said := strings.Join(undone, "\n")
	for _, want := range []string{LinkPrefix + "7", "net.ipv4.ip_forward", TableName, ArpTableName} {
		if !strings.Contains(said, want) {
			t.Errorf("%s isn't reported as undone:\n%s", want, said)
		}
	}
	// Nothing left: nothing to say.
	if undone, err := ClearLeftovers(Options{NewRoot: testNewRoot, RuntimeDir: run}); err != nil || len(undone) != 0 {
		t.Fatalf("again: %q, %v", undone, err)
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
