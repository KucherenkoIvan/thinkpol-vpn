package safety

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// What to do when a surface differs after the restore (the phase-end
// runbook's rollback, kept because it worked).
const (
	nextPfReload = "load the stock rules once more (sudo pfctl -f /etc/pf.conf); still different: reboot. " +
		"Never flush (pfctl -F) or disable (pfctl -d) pf: that turns off other apps' rules"
	nextPfAnchors = "an Apple anchor changed: reboot (the system loads its anchors at boot); never flush them"
	nextPfState   = "pf's state differs from the baseline: if the baseline had it on, sudo pfctl -e; never pfctl -d"
	nextGuard     = "thinkpol's guard anchor holds rules: run thinkpol's rollback (thinkpol up -connect=false, then stop it); " +
		"a reboot clears it; never pfctl -X a reference that isn't thinkpol's"
	nextDNS = "in this order: remove thinkpol's resolver key, turn Wi-Fi off and on, check that no service key holds " +
		"ThinkpolOverride, only then remove State:/Network/thinkpol/DNS and flush the cache"
)

// surfaces are what the core records of a Mac: the pf checks of the
// phase-end runbook (its pfcheck and pfrestore) and DNS. pf is read with
// the guard's own readers (package firewall).
func surfaces() []Surface {
	anchor := func(name, next string) Surface {
		return Surface{Name: "pf-anchor-" + name, Argv: []string{pfctlPath, "-a", "com.apple/" + name, "-s", "rules"}, Norm: pfAnchor, Next: next}
	}
	return []Surface{
		{Name: "pf-info", Argv: []string{pfctlPath, "-s", "info"}, Norm: pfStatus, Next: nextPfState},
		{Name: "pf-rules", Argv: []string{pfctlPath, "-s", "rules"}, Norm: pfListing, Next: nextPfReload},
		{Name: "pf-nat", Argv: []string{pfctlPath, "-s", "nat"}, Norm: pfListing, Next: nextPfReload},
		{Name: "pf-skip", Argv: []string{pfctlPath, "-s", "Interfaces", "-v"}, Norm: pfSkips, Next: nextPfReload},
		anchor("250.ApplicationFirewall", nextPfAnchors),
		anchor("200.AirDrop", nextPfAnchors),
		anchor(strings.TrimPrefix(firewall.GuardAnchor, "com.apple/"), nextGuard),
		// Recorded only: other apps take and drop references, and a
		// flushed anchor's name stays listed until a reboot.
		{Name: "pf-references", Argv: []string{pfctlPath, "-s", "References"}},
		{Name: "pf-anchors", Argv: []string{pfctlPath, "-a", "com.apple", "-s", "Anchors"}},
		{Name: "dns", Argv: []string{scutilPath, "--dns"}, Norm: dnsWithoutReach, Info: true, Next: nextDNS},
	}
}

func failed(out output) error {
	if out.Err != "" {
		return errors.New(out.Err)
	}
	return fmt.Errorf("exit %d: %s", out.Code, strings.Join(firewall.ListingLines(out.Stderr), "; "))
}

// pfStatus is `pfctl -s info`'s Status.
func pfStatus(out output) ([]string, error) {
	if out.Code != 0 {
		return nil, failed(out)
	}
	on, err := firewall.PfEnabled(out.Stdout)
	if err != nil {
		return nil, err
	}
	if on {
		return []string{"Status: Enabled"}, nil
	}
	return []string{"Status: Disabled"}, nil
}

func pfListing(out output) ([]string, error) {
	if out.Code != 0 {
		return nil, failed(out)
	}
	return firewall.ListingLines(out.Stdout), nil
}

// pfAnchor is an anchor's rules; one that doesn't exist holds none.
func pfAnchor(out output) ([]string, error) {
	if out.Code != 0 && bytes.Contains(out.Stderr, []byte("Invalid argument")) {
		return []string{}, nil
	}
	return pfListing(out)
}

// pfSkips are the lines of `pfctl -s Interfaces -v` for skipped names.
func pfSkips(out output) ([]string, error) {
	lines, err := pfListing(out)
	if err != nil {
		return nil, err
	}
	skips := []string{}
	for _, l := range lines {
		if strings.Contains(l, "(skip)") {
			skips = append(skips, l)
		}
	}
	return skips, nil
}

// dnsWithoutReach is `scutil --dns` without its reachability lines, which
// change by themselves.
func dnsWithoutReach(out output) ([]string, error) {
	if out.Code != 0 {
		return nil, failed(out)
	}
	lines := []string{}
	for _, l := range strings.Split(string(out.Stdout), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, "reach") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
