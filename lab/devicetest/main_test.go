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
		!strings.Contains(got, "undo: while pf holds the rules, nat and skips this load set, unless the skip pf listed after it is gone: pfctl -f /etc/pf.conf")) {
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

// The device-run plans' listings, each change and undo checked through
// the core's Describe on a Mac. Their reads are checked against the
// core's allow list beside it (safety's
// TestEveryPlansReadsAndChangesAreTheCores, over plans.All): that check
// is unexported, and a test beside it would move FROZEN.
func TestTheTP143ListingIsEverythingTheRunMayDo(t *testing.T) {
	p, ok := plan.Lookup(allPlans(), "tp-143")
	if !ok {
		t.Fatal("no TP-143 plan")
	}
	got := listing(p, "en7")
	listings := "  root read: pfctl -s Interfaces -v\n  root read: pfctl -s Interfaces -vv\n  root read: pfctl -s info -v\n"
	undone := "  undo now:  the plan's newest change\n  root read: pfctl -s Interfaces -v\n"
	for _, want := range []string{
		"TP-143: ",
		"budget 5m0s",
		"step 1 stock\n" + listings + "step 2 skip-on-lo\n  change:    ",
		listings + undone + "step 3 skip-on-lo0\n  change:    ",
		listings + undone + "then, and on Ctrl-C",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the listing lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "capture:") {
		t.Errorf("a capture listed:\n%s", got)
	}
	if runtime.GOOS == "darwin" && (strings.Count(got, `load pf's main ruleset: "set skip on lo", then /etc/pf.conf`) != 1 ||
		strings.Count(got, `load pf's main ruleset: "set skip on lo0", then /etc/pf.conf`) != 1 ||
		strings.Count(got, "    undo: while pf holds the rules") != 2) {
		t.Errorf("the changes and their undos:\n%s", got)
	}
	if n := strings.Count(got, "root read:"); n != 11 {
		t.Errorf("%d root reads listed, want 11", n)
	}
}

func TestTheTP085ListingIsEverythingTheRunMayDo(t *testing.T) {
	p, ok := plan.Lookup(allPlans(), "tp-085")
	if !ok {
		t.Fatal("no TP-085 plan")
	}
	got := listing(p, "en7")
	for _, want := range []string{
		"TP-085: ",
		"kill switch off",
		`capture: the physical interface (en7), filter "not (udp src port N)", running until the run ends`,
		`(the plan's filter "" with the self-test's controls`,
		"step 1 connect\n  ask you:   With the kill switch off, connect over reality",
		"(waits for Enter; your note is saved)\n  root read: scutil --dns\n  root read: netstat -rn\nstep 2 direct-name\n  ask you:   ",
		"step 3 tunnel-name\n  ask you:   ", "under example.net",
		"step 4 browse\n  ask you:   ",
		"step 5 disconnect\n  ask you:   Disconnect",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the listing lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "change:") || strings.Count(got, "root read:") != 2 || strings.Count(got, "ask you:") != 5 {
		t.Errorf("want no change, 2 root reads, 5 asks:\n%s", got)
	}
}
