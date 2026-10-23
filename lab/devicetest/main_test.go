//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// childEnv makes the test binary devicetest itself: the lab's tests run
// the real launch script, which runs this binary's root modes.
const childEnv = "TPDT_MAIN_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "" {
		os.Exit(m.Run())
	}
	if err := dispatch(os.Args[1], os.Args[2:]); err != nil {
		_, _ = os.Stderr.WriteString("devicetest: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

func TestTheTP096ListingIsEverythingTheRunMayDo(t *testing.T) {
	p, ok := plan.Lookup("tp-096")
	if !ok {
		t.Fatal("no TP-096 plan")
	}
	got := listing(p, "en7")
	for _, want := range []string{
		"TP-096: ",
		"budget 5m0s",
		"exit server: not needed",
		`capture: the physical interface (en7), filter "ip6"`,
		"step 1 stock\n  root read: pfctl -s Interfaces -v\n  root read: pfctl -a com.apple -s Anchors\n  root read: pfctl -s References\n",
		"step 2 skip-on-lo\n  change:    ",
		"  undo now:  the newest change\n  root read: pfctl -s Interfaces -v\n  root read: pfctl -s rules\n",
		"every change undone, newest first",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the listing lacks %q:\n%s", want, got)
		}
	}
	if runtime.GOOS == "darwin" && (!strings.Contains(got, `load pf's main ruleset: "set skip on lo", then /etc/pf.conf`) ||
		!strings.Contains(got, "undo: pfctl -f /etc/pf.conf")) {
		t.Errorf("the change and its undo:\n%s", got)
	}
	if n := strings.Count(got, "root read:"); n != 9 {
		t.Errorf("%d root reads listed, want 9", n)
	}
}

func TestEveryPlanIsValidAndItsReadsAndChangesAreTheCores(t *testing.T) {
	if len(plan.All()) < 2 {
		t.Fatalf("plans: %v", plan.All())
	}
	for _, p := range plan.All() {
		if err := p.Validate(); err != nil {
			t.Error(err)
		}
		for _, st := range p.Steps {
			for _, op := range st.Ops {
				switch {
				case runtime.GOOS != "darwin":
				case op.Kind == plan.RootRead:
					if _, err := safety.RootRead(op.Argv); err != nil {
						t.Errorf("%s %s: %v", p.Ticket, st.Name, err)
					}
				case op.Kind == plan.Do:
					if _, err := changeAction(op.Change); err != nil {
						t.Errorf("%s %s: %v", p.Ticket, st.Name, err)
					}
				}
			}
		}
	}
}

func TestThePrivateConfigIsTheUsersAlone(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, mode os.FileMode) string {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("exit:\n  ssh: exit-host\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write(filepath.Join(base, "cfg", "config.yaml"), 0o600)
	if _, err := loadPrivateConfig(good); err != nil {
		t.Errorf("a 0600 file of the user's: %v", err)
	}
	if err := os.Symlink(good, filepath.Join(base, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "repo", ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"readable by others": write(filepath.Join(base, "open.yaml"), 0o644),
		"a symlink":          filepath.Join(base, "link.yaml"),
		"in a git checkout":  write(filepath.Join(base, "repo", "private", "config.yaml"), 0o600),
		"missing":            filepath.Join(base, "none.yaml"),
	} {
		if _, err := loadPrivateConfig(path); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	t.Setenv("THINKPOL_DEVICETEST_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", base)
	if p, _ := privateConfigPath(""); p != filepath.Join(base, "thinkpol-devicetest", "config.yaml") {
		t.Errorf("default path %s", p)
	}
}

func TestTheSelfTestControls(t *testing.T) {
	if f := controlFilter("ip6", 40002); f != "not (udp src port 40002) and ((ip6) or (udp dst port 9))" {
		t.Errorf("filter %q", f)
	}
	if f := controlFilter("", 40002); f != "not (udp src port 40002)" {
		t.Errorf("filter %q", f)
	}
}
