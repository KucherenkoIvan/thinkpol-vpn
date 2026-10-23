package safety

import (
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
)

// What to do when a surface differs after the restore.
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

// surfaces are what the core compares of a Mac with its baseline: pf's
// main rules, nat rules, skipped interfaces, its state, Apple's AirDrop
// and Application Firewall anchors and thinkpol's guard anchor, every line
// of each; and DNS, a difference there reported only. References and the
// list of anchors are recorded, not compared: other apps take and drop
// references, and a flushed anchor's name stays listed until a reboot.
func surfaces() []surface {
	anchor := func(name, next string) surface {
		return surface{name: "pf-anchor-" + name, argv: []string{pfctlPath, "-a", "com.apple/" + name, "-s", "rules"}, norm: pfAnchor, next: next}
	}
	return []surface{
		{name: "pf-info", argv: []string{pfctlPath, "-s", "info"}, norm: pfStatus, next: nextPfState},
		{name: "pf-rules", argv: []string{pfctlPath, "-s", "rules"}, norm: pfListing, next: nextPfReload},
		{name: "pf-nat", argv: []string{pfctlPath, "-s", "nat"}, norm: pfListing, next: nextPfReload},
		{name: "pf-skip", argv: []string{pfctlPath, "-s", "Interfaces", "-v"}, norm: pfSkips, next: nextPfReload},
		anchor("250.ApplicationFirewall", nextPfAnchors),
		anchor("200.AirDrop", nextPfAnchors),
		anchor(strings.TrimPrefix(firewall.GuardAnchor, "com.apple/"), nextGuard),
		{name: "pf-references", argv: []string{pfctlPath, "-s", "References"}},
		{name: "pf-anchors", argv: []string{pfctlPath, "-a", "com.apple", "-s", "Anchors"}},
		{name: "dns", argv: []string{scutilPath, "--dns"}, norm: dnsWithoutReach, info: true, next: nextDNS},
	}
}

// pfStatus is `pfctl -s info`'s Status, as the guard reads it.
func pfStatus(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, failed(out)
	}
	on, err := firewall.ParsePfEnabled(out.Stdout)
	if err != nil {
		return nil, err
	}
	if on {
		return []string{"Status: Enabled"}, nil
	}
	return []string{"Status: Disabled"}, nil
}

// pfListing is every line of a listing.
func pfListing(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, failed(out)
	}
	return listingLines(out.Stdout), nil
}

// pfAnchor is an anchor's rules; only pfctl's answer about an anchor that
// doesn't exist reads as none.
func pfAnchor(out output) ([]string, error) {
	if out.Code != 0 && out.Err == "" && firewall.AnchorMissing(out.Stderr) {
		return []string{}, nil
	}
	return pfListing(out)
}

// pfSkips are the names pf skips, lo0 included, as the guard reads them.
func pfSkips(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, failed(out)
	}
	names, err := firewall.SkippedNames(out.Stdout)
	if err != nil {
		return nil, err
	}
	return append([]string{}, names...), nil
}

// dnsWithoutReach is `scutil --dns` without its reachability lines, which
// change by themselves.
func dnsWithoutReach(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, failed(out)
	}
	lines := []string{}
	for _, l := range listingLines(out.Stdout) {
		if !strings.Contains(l, "reach") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
