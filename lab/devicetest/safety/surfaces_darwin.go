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
	nextGuard     = "thinkpol's guard anchor holds rules: a reboot clears it; or start thinkpol and stop it again " +
		"(thinkpol up -connect=false, then stop it), which removes its guard; never pfctl -X a reference that isn't thinkpol's"
	nextPfSettings = "pf's limits or timeouts differ from the baseline: loading /etc/pf.conf replaced what another app set; " +
		"restart that app, or reboot"
	nextDNS = "in this order: remove thinkpol's resolver key, turn Wi-Fi off and on, check that no service key holds " +
		"ThinkpolOverride, only then remove State:/Network/thinkpol/DNS and flush the cache"
)

// surfaces are what the core compares of a Mac with its baseline, every
// line of each: pf's state, main rules, nat rules, skipped interfaces (lo0
// included), pool limits (`-s memory`) and global timeouts (`-s
// timeouts`), the last two because loading a ruleset replaces them too;
// Apple's AirDrop and Application Firewall anchors and thinkpol's guard
// anchor. A difference is LEFT, each with what to do; REBOOT comes only
// from the pf-skip undo itself (verdict). DNS is compared and reported
// only. Dummynet rules are recorded and compared as information only:
// pfctl's man page documents no listing of them, so whether `-s dummynet`
// exists is for a device run to show (an unreadable compared surface
// would refuse every run). References and the list of anchors are
// recorded, not compared: other apps take and drop references, and a
// flushed anchor's name stays listed until a reboot.
func surfaces() []surface {
	anchor := func(name, next string) surface {
		return surface{name: "pf-anchor-" + name, argv: []string{pfctlPath, "-a", "com.apple/" + name, "-s", "rules"}, norm: pfAnchor, next: next}
	}
	return []surface{
		{name: "pf-info", argv: []string{pfctlPath, "-s", "info"}, norm: pfStatus, next: nextPfState},
		{name: "pf-rules", argv: []string{pfctlPath, "-s", "rules"}, norm: outputLines, next: nextPfReload},
		{name: "pf-nat", argv: []string{pfctlPath, "-s", "nat"}, norm: outputLines, next: nextPfReload},
		{name: "pf-skip", argv: []string{pfctlPath, "-s", "Interfaces", "-v"}, norm: pfSkips, next: nextPfReload},
		{name: "pf-limits", argv: []string{pfctlPath, "-s", "memory"}, norm: outputLines, next: nextPfSettings},
		{name: "pf-timeouts", argv: []string{pfctlPath, "-s", "timeouts"}, norm: outputLines, next: nextPfSettings},
		{name: "pf-dummynet", argv: []string{pfctlPath, "-s", "dummynet"}, norm: outputLines, info: true, next: nextPfSettings},
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
	if err := checked(out); err != nil {
		return nil, err
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

// pfAnchor is an anchor's rules; only pfctl's answer about an anchor that
// doesn't exist reads as none.
func pfAnchor(out output) ([]string, error) {
	if out.Code != 0 && out.Err == "" && firewall.AnchorMissing(out.Stderr) {
		return []string{}, nil
	}
	return outputLines(out)
}

// pfSkips are the names pf skips, lo0 included, as the guard reads them.
func pfSkips(out output) ([]string, error) {
	if err := checked(out); err != nil {
		return nil, err
	}
	return firewall.SkippedNames(out.Stdout)
}

// dnsWithoutReach is `scutil --dns` without its reachability lines, which
// change by themselves.
func dnsWithoutReach(out output) ([]string, error) {
	all, err := outputLines(out)
	if err != nil {
		return nil, err
	}
	lines := []string{}
	for _, l := range all {
		if !strings.Contains(l, "reach") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
