//go:build linux && !android

package supervisor_test

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread/nsthreadtest"
)

// Setting a space's sysctls many times, one after another and then at once,
// writes them in the space's namespace and leaves every supervisor thread,
// the main one included, in the node's own namespaces.
func TestSetNetSysctlsLeavesNoThreadBehind(t *testing.T) {
	needsLab(t)
	name := "tp-sysctl-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	ns, err := os.Open("/run/netns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close() }()

	const key = "net/ipv4/conf/all/rp_filter"
	set := func(value string) error {
		return supervisor.SetNetSysctls(int(ns.Fd()), map[string]string{key: value})
	}
	check := func(want string) {
		t.Helper()
		out, err := exec.Command("ip", "netns", "exec", name, "cat", "/proc/sys/"+key).CombinedOutput()
		if err != nil {
			t.Fatalf("read %s: %v: %s", key, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Fatalf("%s in the namespace is %q, want %q", key, got, want)
		}
	}

	for range 100 {
		if err := set("1"); err != nil {
			t.Fatal(err)
		}
	}
	check("1")
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- set("2")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	check("2")
	nsthreadtest.CheckThreadsHome(t)
}
