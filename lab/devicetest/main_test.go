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
	os.Exit(safety.RootMain(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
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
		`capture: the physical interface (en7), filter "not (udp src port N) and ((ip6) or (udp dst port 9))", running until the run ends; its pcap is kept in the evidence`,
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
		!strings.Contains(got, "undo: while pf skips other than at the baseline and holds the rules, nat and skips this load set: pfctl -f /etc/pf.conf")) {
		t.Errorf("the change and its undo:\n%s", got)
	}
	if n := strings.Count(got, "root read:"); n != 9 {
		t.Errorf("%d root reads listed, want 9", n)
	}
}

func TestTheFilterLetsThePositiveMarkerThroughAndNeverTheNegative(t *testing.T) {
	if f := controlFilter("ip6", "40002"); f != "not (udp src port 40002) and ((ip6) or (udp dst port 9))" {
		t.Errorf("filter %q", f)
	}
	if f := controlFilter("", "40002"); f != "not (udp src port 40002)" {
		t.Errorf("filter %q", f)
	}
}

// A change the core refuses is listed with the core's reason.
func TestAChangeTheCoreRefusesIsListedWithItsReason(t *testing.T) {
	if got := describeOp(plan.Do(plan.PfSkip("lo; anchor x"))); !strings.Contains(got, "pf-skip, refused: ") {
		t.Errorf("listed as %q", got)
	}
}
