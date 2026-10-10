package lab_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Runs only inside a lab node (make lab-gotest, or Node.RunGoTests), where
// it proves tests get root and network namespaces.
func TestInsideLabNetns(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	ns := "lab-inside-" + strings.ReplaceAll(t.Name(), "/", "-")
	ip("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	ip("-n", ns, "link", "add", "dummy0", "type", "dummy")
	ip("-n", ns, "addr", "add", "fd00:1ab::1/64", "dev", "dummy0")
	if out := ip("-n", ns, "addr", "show", "dummy0"); !strings.Contains(out, "fd00:1ab::1/64") {
		t.Errorf("address not set in the namespace: %s", out)
	}
	if out := ip("link", "show"); strings.Contains(out, "dummy0") {
		t.Error("the namespace's link leaked into the node's own namespace")
	}
}
