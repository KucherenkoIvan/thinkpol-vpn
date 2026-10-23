//go:build darwin || linux

package main

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// childEnv makes the test binary devicetest-root: the lab's tests run the
// real launch script, which runs the root modes of the binary it copies.
const childEnv = "TPDT_MAIN_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "" {
		os.Exit(m.Run())
	}
	ctx, args := context.Background(), os.Args[2:]
	var err error
	switch os.Args[1] {
	case "helper":
		err = safety.HelperMain(ctx, args, os.Stdin, os.Stdout, os.Stderr)
	case "deadman":
		err = safety.DeadmanMain(ctx, args)
	case "root-restore":
		err = safety.RestoreMain(ctx, args, os.Stdout)
	}
	if err != nil {
		_, _ = os.Stderr.WriteString("devicetest-root: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

func TestTheTP096ListingIsEverythingTheRunMayDo(t *testing.T) {
	p, ok := plan.Lookup(allPlans(), "tp-096")
	if !ok {
		t.Fatal("no TP-096 plan")
	}
	got := listing(p, "en7")
	for _, want := range []string{
		"TP-096: ",
		"budget 5m0s",
		`capture: the physical interface (en7), filter "ip6", running until the run ends; its pcap is kept in the evidence`,
		"step 1 stock\n  root read: pfctl -s Interfaces -v\n  root read: pfctl -a com.apple -s Anchors\n  root read: pfctl -s References\n",
		"step 2 skip-on-lo\n  change:    ",
		"  undo now:  the plan's newest change\n  root read: pfctl -s Interfaces -v\n  root read: pfctl -s rules\n",
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

func TestEveryPlansReadsAndChangesAreTheCores(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the plans are macOS's")
	}
	for _, p := range allPlans() {
		for _, st := range p.Steps {
			for _, op := range st.Ops {
				var err error
				switch op.Kind {
				case plan.OpRead:
					_, err = safety.RootRead(op.Argv)
				case plan.OpDo:
					_, _, err = describeChange(op.Change)
				}
				if err != nil {
					t.Errorf("%s %s: %v", p.Ticket, st.Name, err)
				}
			}
		}
	}
}

func TestTheFilterLetsThePositiveMarkerThroughAndNeverTheNegative(t *testing.T) {
	if f := controlFilter("ip6", 40002); f != "not (udp src port 40002) and ((ip6) or (udp dst port 9))" {
		t.Errorf("filter %q", f)
	}
	if f := controlFilter("", 40002); f != "not (udp src port 40002)" {
		t.Errorf("filter %q", f)
	}
}
