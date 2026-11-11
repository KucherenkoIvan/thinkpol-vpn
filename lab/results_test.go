//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// TestCensorMatrix scores every transport against every censor module
// (PRD C4, success metric 1) and regenerates lab/RESULTS.md. Every cell is
// probed in its own lab, and a transport's censored cells run in parallel:
// a transport passes when its data crossed the censor in the lab router
// over IPv4 and over IPv6, fails when it crossed over neither, and is
// partial when only one family crossed, which only a row that varies
// (censorCase.varies) may be. A cell whose outcome contradicts what its
// censor means to produce fails the test, and a cell whose censor can't be
// trusted (censord died, the kernel dropped queued packets, an active
// module missed a snapshot, the verdict log doesn't show the probe's flows,
// the module the cell quotes didn't compare what it must) is an error.
// RESULTS.md is written only by a complete run with no error.
//
// A transport's off cell (no censor) runs before its censored cells and
// they read its result: a transport must pass without a censor before it
// is judged against one. A censored cell without a passing off cell is an
// error and fails fast, whether the off cell didn't run (a -run filter can
// select the cell alone) or it failed. Every cell holds its own lab slot
// (lab.StartOwnSlot).
func TestCensorMatrix(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		cells []matrixCell
	)
	record := func(cell matrixCell) {
		mu.Lock()
		defer mu.Unlock()
		cells = append(cells, cell)
	}
	t.Cleanup(func() { writeResults(t, cells, len(transports)*len(censorCases)) })

	// runCell probes one cell and records it: t.Fatal below ends the
	// function before its return, the deferred record is what survives.
	runCell := func(t *testing.T, tr transport, cc censorCase) matrixCell {
		cell := matrixCell{transport: tr.name, censor: cc.name, result: "error"}
		defer func() { record(cell) }()

		topology := lab.Standard()
		if cc.upstream || tr.upstream {
			topology = lab.Upstream()
		}
		l := lab.StartOwnSlot(t, topology)
		target, err := tr.setup(t, l)
		if err != nil {
			cell.detail = "setup failed"
			t.Fatal(err)
		}
		var c *censorRun
		if cc.modules != nil {
			c = startCensor(t, l, cc.modules(t, l))
		}

		want := cc.want(tr.name)
		if cc.settle {
			// An active module judges a connection after it has crossed:
			// the first probe shows it the transport, the cell is the
			// probe after its verdicts.
			tr.probe(t, l, target, false)
			if err := c.settled(t, l); err != nil {
				cell.result, cell.detail = "error", "the active modules didn't settle"
				t.Fatal(err)
			}
		}
		got := tr.probe(t, l, target, want == "pass")
		cell.result, cell.detail = score(got)

		if c != nil {
			if err := c.healthy(t); err != nil {
				cell.result, cell.detail = "error", "censor unhealthy"
				t.Fatal(err)
			}
			if err := tr.sawFlows(t, l, c); err != nil {
				cell.result, cell.detail = "error", "the verdict log misses the probe's flows"
				t.Fatal(err)
			}
		}
		if want == "fail" || want == "varies" && cell.result != "pass" {
			how, err := blockedBy(t, l, c, cc.blocker, got, tr.oneUnderlay)
			if err != nil {
				t.Error(err)
			} else if cell.result != "pass" {
				cell.detail += "; the censor " + how + " them"
			}
		}
		if want == "varies" {
			cell.detail = strings.TrimPrefix(cell.detail+"; varies: "+cc.varies[tr.name], "; ")
			want = cell.result
		}
		if cc.report != "" {
			why := c.judged(t, l, cc.report)
			if why != "" {
				cell.detail = strings.TrimPrefix(cell.detail+"; "+cc.report+": "+why, "; ")
			}
			if err := cc.verdictMisses(tr.name, why); err != nil {
				cell.result, cell.detail = "error", err.Error()
				t.Fatalf("%s against %s: %v", tr.name, cc.name, err)
			}
		}
		if cell.result != want {
			t.Errorf("%s against %s: %s (%s), want %s", tr.name, cc.name, cell.result, cell.detail, want)
		}
		return cell
	}

	off, censored := censorCases[0], censorCases[1:]
	if off.modules != nil {
		t.Fatalf("censor case %q is the off cell and must have no censor", off.name)
	}
	for _, cc := range censored {
		if cc.modules == nil {
			t.Fatalf("censor case %q has no censor: only censorCases[0] may be off", cc.name)
		}
		for tr, want := range cc.expect {
			if want == "fail" && cc.blocker == "" {
				t.Fatalf("censor case %q expects %s to fail but names no blocker", cc.name, tr)
			}
		}
		if len(cc.varies) > 0 && cc.blocker == "" {
			t.Fatalf("censor case %q has rows that vary but names no blocker", cc.name)
		}
		for tr := range cc.varies {
			if !strings.HasSuffix(tr, " (reference)") {
				t.Fatalf("censor case %q lets %s vary: only a reference row may, a gate row's result is never chance", cc.name, tr)
			}
		}
		if len(cc.verdictSays) > 0 && cc.report == "" {
			t.Fatalf("censor case %q checks verdicts but names no module to report", cc.name)
		}
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			offResult := "" // the off cell's result; "" when it didn't run
			t.Run(off.name, func(t *testing.T) {
				// runCell records the cell even when t.Fatal stops it,
				// but the assignment would not happen: claim that the
				// cell ran before it can fail.
				offResult = "error"
				offResult = runCell(t, tr, off).result
			})
			for _, cc := range censored {
				t.Run(cc.name, func(t *testing.T) {
					t.Parallel()
					if offResult == "" {
						record(matrixCell{transport: tr.name, censor: cc.name,
							result: "error", detail: gateNotRun})
						t.Fatal(gateNotRun)
					}
					if offResult != "pass" {
						record(matrixCell{transport: tr.name, censor: cc.name,
							result: "error", detail: gateNotPassed})
						t.Fatal(gateNotPassed)
					}
					runCell(t, tr, cc)
				})
			}
		})
	}
}

// The off-cell gate messages: a censored cell sees them when its baseline
// didn't run or didn't pass.
const (
	gateNotRun    = "the off cell didn't run"
	gateNotPassed = "the off cell didn't pass"
)

type matrixCell struct {
	transport, censor, result, detail string
}

// crossed is what a probe found: whether data crossed over each family.
type crossed struct{ v4, v6 bool }

// score is a cell's result: pass when data crossed over both families,
// fail when it crossed over neither, and partial when only one did, which
// only a row that varies may be: a blocking censor that one family slips
// past leaks, and a transport that loses a family doesn't pass.
func score(c crossed) (result, detail string) {
	switch {
	case c.v4 && c.v6:
		return "pass", ""
	case c.v4:
		return "partial", "only IPv4 crossed"
	case c.v6:
		return "partial", "only IPv6 crossed"
	}
	return "fail", "neither IPv4 nor IPv6 crossed"
}

// TestScore: a cell meant to block, where one family still crossed, is
// not the fail it expects, and neither is a cell meant to pass.
func TestScore(t *testing.T) {
	for _, c := range []struct {
		crossed crossed
		want    string
	}{
		{crossed{v4: true, v6: true}, "pass"},
		{crossed{}, "fail"},
		{crossed{v4: true}, "partial"},
		{crossed{v6: true}, "partial"},
	} {
		if got, _ := score(c.crossed); got != c.want {
			t.Errorf("%+v scored %s, want %s", c.crossed, got, c.want)
		}
	}
	blocking := censorCase{expect: map[string]string{rowPlainTCP: "fail"}}
	for _, leak := range []crossed{{v4: true}, {v6: true}} {
		if got, _ := score(leak); got == blocking.want(rowPlainTCP) {
			t.Errorf("a one-family leak %+v scores %s, what a blocking cell expects", leak, got)
		}
	}
}

type censorCase struct {
	name string
	// expect is each transport's result when the censor works as meant;
	// a transport not in it must pass.
	expect  map[string]string
	modules func(t *testing.T, l *lab.Lab) []censor.ModuleConfig // nil: no censord
	// varies holds the rows whose result is chance, with why: any result
	// is accepted, and a family that didn't cross must be the blocker's.
	varies map[string]string
	// blocker is the module a cell expected to fail must find blocking
	// in the verdict log.
	blocker string
	// upstream runs the cell in lab.Upstream: the camouflage site behind
	// the router.
	upstream bool
	// settle probes twice, the cell scoring the second, once the active
	// modules have flagged every flow of server-1 a module tagged.
	settle bool
	// report names the module whose first flag of a connection from
	// device-a to server-1 the cell's detail quotes.
	report string
	// verdictSays holds the rows whose report verdict must say something,
	// the comparison the cell is for: a verdict without it ("not
	// compared", or no flag at all) is an error, never a pass.
	verdictSays map[string]string
}

// verdictMisses is an error when row's verdict from the report module,
// why ("" for no flag), lacks what the case needs it to say: the module
// didn't compare what the cell is for, which must not score as a pass.
func (cc censorCase) verdictMisses(row, why string) error {
	says, ok := cc.verdictSays[row]
	if !ok || strings.Contains(why, says) {
		return nil
	}
	if why == "" {
		return fmt.Errorf("%s never flagged the row's connection, want a verdict saying %q", cc.report, says)
	}
	return fmt.Errorf("%s's verdict %q doesn't say %q", cc.report, why, says)
}

// TestVerdictMisses: a cell whose module didn't compare ("not compared",
// or no flag at all) is an error, whatever the row's crossing scored.
func TestVerdictMisses(t *testing.T) {
	cc := censorCase{report: "server-hello", verdictSays: map[string]string{rowHTTPS: "server hello matches the site"}}
	for why, wantErr := range map[string]bool{
		"accept, server hello matches the site camouflage.example.net": false,
		"accept, not compared: the site is unreachable":                true,
		"": true,
	} {
		if err := cc.verdictMisses(rowHTTPS, why); (err != nil) != wantErr {
			t.Errorf("verdict %q: %v, want an error: %v", why, err, wantErr)
		}
	}
	if err := cc.verdictMisses(rowPlainTCP, ""); err != nil {
		t.Errorf("a row the case doesn't check: %v", err)
	}
}

func (cc censorCase) want(transport string) string {
	if _, ok := cc.varies[transport]; ok {
		return "varies"
	}
	if w, ok := cc.expect[transport]; ok {
		return w
	}
	return "pass"
}

// Row names. The control rows are no transports: plain TCP and HTTPS on
// the underlay, what a TLS-shaped transport rides, cross the censor. The
// reference rows are real WireGuard and OpenVPN, what the fingerprint
// modules must block.
const (
	rowUDP        = "udp"
	rowPlainTCP   = "plain-tcp (control)"
	rowHTTPS      = "https (control)"
	rowWireGuard  = "wireguard (reference)"
	rowOpenVPNUDP = "openvpn-udp (reference)"
	rowOpenVPNTCP = "openvpn-tcp (reference)"
	rowRandomTCP  = "random-tcp (reference)"
	rowRelayTCP   = "relay-tcp (reference)"
)

// allFail expects every row to fail.
func allFail() map[string]string {
	m := map[string]string{}
	for _, tr := range transports {
		m[tr.name] = "fail"
	}
	return m
}

var censorCases = []censorCase{
	{name: "off"},
	// Lists that name neither server-1 nor the https row's site: plain
	// HTTPS to an unlisted site passes, and so does everything else.
	{name: "blocklists (elsewhere)", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return []censor.ModuleConfig{
			{Name: "ip-blocklist", Settings: json.RawMessage(`{"addresses": ["203.0.113.9", "2001:db8::/32"]}`)},
			{Name: "sni-blocklist", Settings: json.RawMessage(`{"names": ["blocked.example.net"]}`)},
		}
	}},
	{name: "ip-blocklist (entry)", expect: allFail(), blocker: "ip-blocklist",
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig { return entryIPBlocklist(t, l) }},
	// Reset, its default: plain TCP, OpenVPN over TCP and the rest name
	// no site; the relay's clients name the site it relays to.
	{name: "sni-blocklist (entry)", expect: map[string]string{rowHTTPS: "fail", rowRelayTCP: "fail"}, blocker: "sni-blocklist",
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "sni-blocklist", Settings: json.RawMessage(`{"names": ["` + httpsName + `"]}`)}}
		}},
	// thinkpol's udp carries WireGuard, but nothing on its wire looks like
	// it (C1, TestM0): it passes.
	{name: "wireguard-fingerprint", expect: map[string]string{rowWireGuard: "fail"}, blocker: "wireguard-fingerprint",
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "wireguard-fingerprint", Settings: json.RawMessage(`{}`)}}
		}},
	{name: "openvpn-fingerprint", expect: map[string]string{rowOpenVPNUDP: "fail", rowOpenVPNTCP: "fail"}, blocker: "openvpn-fingerprint",
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "openvpn-fingerprint", Settings: json.RawMessage(`{}`)}}
		}},
	// An M2 gate check (docs/design/milestones.md): no row carries
	// WireGuard in TLS yet, so every row passes. A TLS-shaped transport's
	// pass means something only when its probe runs long enough for the
	// rhythm to show: three rekeys (up to 7 minutes, up to about 10
	// minutes when batched), or three idle keepalives.
	{name: "wireguard-rhythm", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return []censor.ModuleConfig{{Name: "wireguard-rhythm", Settings: json.RawMessage(`{}`)}}
	}},
	// M2 gate checks (docs/design/milestones.md). Wu et al.'s exemptions
	// on each connection's first data, UDP's first datagram too: thinkpol's
	// udp sends random bytes first (exempt by chance about once in 400
	// tunnels: six printable bytes first); OpenVPN's first packet is mostly
	// zeros, and HTTPS starts with a TLS record. A WireGuard initiation
	// ends in 16 zero bytes, and is exempt about one time in four.
	{name: "fully-encrypted", expect: map[string]string{rowUDP: "fail", rowRandomTCP: "fail"},
		varies: map[string]string{rowWireGuard: "a WireGuard initiation (mac2's 16 zero bytes) averages about 3.47 set bits per byte, " +
			"and Wu et al.'s first exemption (3.4 or fewer) passes about one in four, its tunnel with it"},
		blocker: "fully-encrypted",
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "fully-encrypted", Settings: json.RawMessage(`{}`)}}
		}},
	// The prober probes every TCP server-1 serves data on, and what
	// fully-encrypted finds suspect (its UDP suspects it doesn't probe),
	// against nginx on the camouflage node: the https row's nginx answers
	// every probe and the TLS handshake as it does; the echo server and
	// OpenVPN don't; the relay answers as the site does, the site's own
	// answers, and shows the upstream tell.
	{name: "active prober", expect: map[string]string{rowRandomTCP: "fail", rowOpenVPNTCP: "fail", rowRelayTCP: "fail"}, blocker: "prober",
		upstream: true, settle: true, report: "prober",
		verdictSays: map[string]string{rowHTTPS: "TLS: the server", rowRelayTCP: "upstream tell: a connection"},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			camouflage := startCamouflage(t, l)
			return []censor.ModuleConfig{
				{Name: "fully-encrypted", Settings: json.RawMessage(`{"tagOnly": true}`)},
				{Name: "prober", Settings: proberSettings(t, l, camouflage)},
			}
		}},
	// The https and relay rows' ClientHellos name the camouflage site:
	// their server hellos are compared with the site's answer to the same
	// ClientHello (the relay's is the site's own).
	{name: "server-hello", upstream: true, settle: true, report: "server-hello",
		verdictSays: map[string]string{rowHTTPS: "server hello matches the site", rowRelayTCP: "server hello matches the site"},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			camouflage := startCamouflage(t, l)
			b, err := json.Marshal(map[string]map[string]string{"sites": {httpsName: camouflage[0].String()}})
			if err != nil {
				t.Fatal(err)
			}
			return []censor.ModuleConfig{{Name: "server-hello", Settings: b}}
		}},
}

// entryIPBlocklist lists server-1's addresses.
func entryIPBlocklist(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
	t.Helper()
	b, err := json.Marshal(map[string][]string{"addresses": {
		l.Node(lab.Server1).IPv4(lab.NetServers).String(),
		l.Node(lab.Server1).IPv6(lab.NetServers).String(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return []censor.ModuleConfig{{Name: "ip-blocklist", Settings: b}}
}

// probeTarget is what a probe sends to: overlay addresses for a transport,
// server-1's own for the control.
type probeTarget struct{ v4, v6 netip.Addr }

type transport struct {
	name  string
	setup func(t *testing.T, l *lab.Lab) (probeTarget, error)
	// probe reports whether data crossed over each family; wantPass gives
	// it time to retry, otherwise it settles a blocked family quickly.
	probe func(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed
	// sawFlows checks the verdict log has the probe's flows on the
	// underlay: the censor saw what it judged.
	sawFlows func(t *testing.T, l *lab.Lab, c *censorRun) error
	// upstream runs every cell of the row in lab.Upstream.
	upstream bool
	// oneUnderlay: both overlay families ride one underlay family, so a
	// blocked cell may blame either family's underlay.
	oneUnderlay bool
}

var transports = []transport{
	{name: rowPlainTCP, setup: setupPlainTCP, probe: probePlainTCP, sawFlows: sawPlainTCP},
	{name: rowHTTPS, setup: setupHTTPS, probe: probeHTTPSOn(443), sawFlows: sawHTTPS},
	{name: rowUDP, setup: setupUDP, probe: probeUDP, sawFlows: sawUDP, oneUnderlay: true},
	{name: rowWireGuard, setup: setupWireGuard, probe: probeUDP, sawFlows: sawWireGuard},
	{name: rowOpenVPNUDP, setup: openVPN{"udp"}.setup, probe: openVPN{"udp"}.probe, sawFlows: openVPN{"udp"}.sawFlows},
	{name: rowOpenVPNTCP, setup: openVPN{"tcp"}.setup, probe: openVPN{"tcp"}.probe, sawFlows: openVPN{"tcp"}.sawFlows},
	{name: rowRandomTCP, setup: setupRandom, probe: probeRandom, sawFlows: sawRandom},
	{name: rowRelayTCP, setup: setupRelay, probe: probeHTTPSOn(relayRowPort), sawFlows: sawRelay, upstream: true},
}

// probeWindow is how long a probe retries a family that should cross; one
// that should not gets blockedWindow.
const probeWindow, blockedWindow = 30 * time.Second, 8 * time.Second

func window(wantPass bool) time.Duration {
	if wantPass {
		return probeWindow
	}
	return blockedWindow
}

func setupPlainTCP(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server := l.Node(lab.Server1)
	listenTCP(t, server)
	return probeTarget{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

func probePlainTCP(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: mustProbe(t)(tcpCrosses(dev, to.v4, window(wantPass))),
		v6: mustProbe(t)(tcpCrosses(dev, to.v6, window(wantPass))),
	}
}

func sawPlainTCP(t *testing.T, l *lab.Lab, c *censorRun) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		dst := serverAddrFor(server, src)
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Src == src && e.Key.Dst == dst && e.Key.DstPort == tcpProbePort
		}) {
			return fmt.Errorf("no TCP flow %s -> %s:%d in the verdict log", src, dst, tcpProbePort)
		}
	}
	return nil
}

func setupUDP(t *testing.T, l *lab.Lab) (probeTarget, error) {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	upDev := dev.Start(t, "thinkpol", "up")
	upSrv := server.Start(t, "thinkpol", "up", "-mode", "server")
	applied := applied(version)
	if err := waitOutput(upSrv, applied, 60*time.Second); err != nil {
		return probeTarget{}, fmt.Errorf("server-1: %w", err)
	}
	if err := waitOutput(upDev, applied, 60*time.Second); err != nil {
		return probeTarget{}, fmt.Errorf("device-a: %w", err)
	}
	if err := waitOutput(upDev, `link up`, 60*time.Second); err != nil {
		return probeTarget{}, err
	}
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// probeUDP pings server-1's overlay addresses, IPv4 and IPv6, through the
// tunnel.
func probeUDP(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: mustProbe(t)(pingCrosses(dev, to.v4, window(wantPass), pingNoReply)),
		v6: mustProbe(t)(pingCrosses(dev, to.v6, window(wantPass), pingNoReply)),
	}
}

// sawUDP: the tunnel runs over one underlay family (m0.yaml's first
// endpoint), so the log needs UDP from device-a to server-1 in either.
func sawUDP(t *testing.T, l *lab.Lab, c *censorRun) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	if !c.logged(t, func(e verdictLine) bool {
		return e.Key.Proto == censor.ProtoUDP &&
			(e.Key.Src == dev.IPv4(lab.NetDevices) && e.Key.Dst == server.IPv4(lab.NetServers) ||
				e.Key.Src == dev.IPv6(lab.NetDevices) && e.Key.Dst == server.IPv6(lab.NetServers))
	}) {
		return fmt.Errorf("no UDP flow device-a -> server-1 in the verdict log")
	}
	return nil
}

// blockedBy checks the verdict log blamed the case's blocker for the
// blocked cell: it dropped or reset packets to or from server-1 over each
// family that didn't cross (over either, for a row whose tunnels share one
// underlay family). It returns which.
func blockedBy(t *testing.T, l *lab.Lab, c *censorRun, blocker string, got crossed, oneUnderlay bool) (string, error) {
	if c == nil {
		return "", fmt.Errorf("a blocking cell without a censor")
	}
	server := l.Node(lab.Server1)
	var families [][]netip.Addr
	switch {
	case oneUnderlay:
		families = append(families, serverAddrs(server))
	default:
		if !got.v4 {
			families = append(families, []netip.Addr{server.IPv4(lab.NetServers)})
		}
		if !got.v6 {
			families = append(families, []netip.Addr{server.IPv6(lab.NetServers)})
		}
	}
	found := map[censor.Verdict]bool{}
	for _, addrs := range families {
		blocked := false
		for _, v := range []censor.Verdict{censor.Drop, censor.Reset} {
			if c.logged(t, blames(blocker, v, addrs)) {
				found[v], blocked = true, true
			}
		}
		if !blocked {
			return "", fmt.Errorf("data to %v didn't cross, but the verdict log has no %s drop or reset of its traffic", addrs, blocker)
		}
	}
	var verdicts []string
	for _, v := range []censor.Verdict{censor.Drop, censor.Reset} {
		if found[v] {
			verdicts = append(verdicts, map[censor.Verdict]string{censor.Drop: "dropped", censor.Reset: "reset"}[v])
		}
	}
	return strings.Join(verdicts, " and "), nil
}

// blames matches a verdict log entry of blocker's verdict v on traffic to
// or from one of addrs.
func blames(blocker string, v censor.Verdict, addrs []netip.Addr) func(verdictLine) bool {
	return func(e verdictLine) bool {
		return e.Verdict == v && e.Module == blocker && (slices.Contains(addrs, e.Key.Dst) || slices.Contains(addrs, e.Key.Src))
	}
}

// TestBlames: a blocker's drop of one family's traffic doesn't blame it
// for the other's.
func TestBlames(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	dev4 := netip.MustParseAddr("192.0.2.1")
	e := verdictLine{LogEntry: censor.LogEntry{Module: "fully-encrypted", Verdict: censor.Drop}, Key: censor.FlowKey{Proto: censor.ProtoUDP, Src: dev4, Dst: v4}}
	for _, c := range []struct {
		addrs []netip.Addr
		want  bool
	}{{[]netip.Addr{v4}, true}, {[]netip.Addr{v6}, false}, {[]netip.Addr{v4, v6}, true}} {
		if got := blames("fully-encrypted", censor.Drop, c.addrs)(e); got != c.want {
			t.Errorf("a drop to %s blames %v: %v, want %v", v4, c.addrs, got, c.want)
		}
	}
	if blames("prober", censor.Drop, []netip.Addr{v4})(e) || blames("fully-encrypted", censor.Reset, []netip.Addr{v4})(e) {
		t.Error("blamed another module or verdict")
	}
}

func waitOutput(p *lab.Process, pattern string, timeout time.Duration) error {
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(timeout)
	for {
		if re.MatchString(p.Output()) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no %q within %s, last output:\n%s", pattern, timeout, p.Output())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// pingCrosses pings until a reply comes or within runs out (untilAnswer):
// "doesn't cross" is a failed ping noReply accepts (pingNoReply: only
// ping's own "no reply"), any other failure an error.
func pingCrosses(from *lab.Node, to netip.Addr, within time.Duration, noReply func(lab.Result) bool) (bool, error) {
	return untilAnswer(within, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := from.Exec(ctx, "ping", "-c", "1", "-W", "1", to.String())
		switch {
		case err == nil:
			return true, nil
		case noReply(res):
			return false, nil
		}
		return false, fmt.Errorf("ping %s from %s: %w\n%s", to, from.Name, err, res.Stdout)
	})
}

// mustProbe passes a probe's answer on and fails the cell (an "error"
// cell, not a blocked one) when the probe got none.
func mustProbe(t *testing.T) func(bool, error) bool {
	return func(crossed bool, err error) bool {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return crossed
	}
}

const (
	censorQueue   = 100
	censorLogPath = "/run/censor/verdicts.jsonl"
)

// censorRun is censord running in the lab router, with the kernel's queue
// counters from when it became ready.
type censorRun struct {
	router *lab.Node
	proc   *lab.Process
	start  censor.QueueStats
}

func startCensor(t *testing.T, l *lab.Lab, modules []censor.ModuleConfig) *censorRun {
	t.Helper()
	b, err := json.Marshal(censor.Config{Queue: censorQueue, Log: censorLogPath, Modules: modules})
	if err != nil {
		t.Fatal(err)
	}
	router := l.Node(lab.Router)
	router.WriteFile(t, "/run/censor/config.json", b)
	p := router.Start(t, "censord", "-config", "/run/censor/config.json")
	lab.Eventually(t, 30*time.Second, func() error {
		if !strings.Contains(p.Output(), "censor ready") {
			return fmt.Errorf("censord not ready yet:\n%s", p.Output())
		}
		return nil
	})
	c := &censorRun{router: router, proc: p}
	if c.start, err = c.stats(); err != nil {
		t.Fatal(err)
	}
	t.Logf("queue %d when censord was ready: %+v", censorQueue, c.start)
	return c
}

func (c *censorRun) stats() (censor.QueueStats, error) {
	out, err := execRead(c.router, execTimeout, "cat", "/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return censor.QueueStats{}, err
	}
	return censor.ParseQueueStats(out, censorQueue)
}

// healthy is nil when censord is still running, the kernel dropped
// nothing on the way to it since it became ready, and every active module
// was handed every snapshot: one it missed (a new flow, a tag) is a
// connection it judged without, a dropped new flow clearing an entry of
// the upstream tell.
func (c *censorRun) healthy(t *testing.T) error {
	select {
	case <-c.proc.Done():
		return fmt.Errorf("censord exited: %v\n%s", c.proc.Err(), c.proc.Output())
	default:
	}
	log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
	if err != nil {
		return err
	}
	var missed verdictLine
	if _, err := matchVerdicts(completeLines(log), func(e verdictLine) bool {
		if e.Event == censor.EventUnnoticed {
			missed = e
			return true
		}
		return false
	}); err != nil {
		return err
	}
	if missed.Event != "" {
		return fmt.Errorf("an active module missed a snapshot: %s %s (%s)", missed.Flow, missed.Module, missed.Reason)
	}
	now, err := c.stats()
	if err != nil {
		return err
	}
	if now.QueueDropped > c.start.QueueDropped || now.UserDropped > c.start.UserDropped {
		return fmt.Errorf("the kernel dropped queued packets: queue_dropped %d -> %d, user_dropped %d -> %d",
			c.start.QueueDropped, now.QueueDropped, c.start.UserDropped, now.UserDropped)
	}
	return nil
}

// verdictLine is a verdict log entry with its flow parsed.
type verdictLine struct {
	censor.LogEntry
	Key censor.FlowKey
}

// logged reports whether a verdict log entry matches, waiting briefly for
// the log to catch up. A failed read is retried; "no" comes only from a
// read that succeeded after the deadline, and the test fails if none
// does. A whole line that doesn't parse fails the test (censord writes
// whole lines); the part after the last newline is a write in progress,
// left for the next read.
func (c *censorRun) logged(t *testing.T, match func(verdictLine) bool) bool {
	t.Helper()
	found, err := c.pollLog(match)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func (c *censorRun) pollLog(match func(verdictLine) bool) (bool, error) {
	deadline := time.Now().Add(3 * time.Second)
	giveUp := deadline.Add(30 * time.Second)
	for {
		log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
		if err == nil {
			found, err := matchVerdicts(completeLines(log), match)
			switch {
			case err != nil:
				return false, err // a whole line: not transient
			case found:
				return true, nil
			case time.Now().After(deadline):
				return false, nil
			}
		} else if time.Now().After(giveUp) {
			return false, fmt.Errorf("reading the verdict log: %w", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// completeLines is s up to its last newline: what a reader racing the
// writer can trust.
func completeLines(s string) string {
	return s[:strings.LastIndexByte(s, '\n')+1]
}

// matchVerdicts says whether a line of log matches; a line that isn't a
// verdict entry is an error.
func matchVerdicts(log string, match func(verdictLine) bool) (bool, error) {
	for _, line := range strings.Split(log, "\n") {
		if line == "" {
			continue
		}
		var e verdictLine
		if err := json.Unmarshal([]byte(line), &e.LogEntry); err != nil {
			return false, fmt.Errorf("verdict log line %q: %w", line, err)
		}
		key, err := censor.ParseFlowKey(e.Flow)
		if err != nil {
			continue // not TCP or UDP
		}
		e.Key = key
		if match(e) {
			return true, nil
		}
	}
	return false, nil
}

func writeResults(t *testing.T, cells []matrixCell, expected int) {
	t.Helper()
	if len(cells) < expected {
		t.Logf("partial matrix run (%d of %d cells): RESULTS.md not written", len(cells), expected)
		return
	}
	for _, c := range cells {
		if c.result == "error" {
			t.Logf("cell %s / %s errored: RESULTS.md not written", c.transport, c.censor)
			return
		}
	}
	if t.Failed() {
		t.Log("the matrix test failed: RESULTS.md not written")
		return
	}
	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(cells, func(a, b matrixCell) int {
		if c := strings.Compare(a.transport, b.transport); c != 0 {
			return c
		}
		return strings.Compare(a.censor, b.censor)
	})
	var b strings.Builder
	b.WriteString("# Censor lab results\n\n")
	b.WriteString("<!-- Generated by `make lab` (TestCensorMatrix); do not edit. -->\n\n")
	b.WriteString("Did a transport's data cross the censor in the lab router, device-a to server-1: " +
		"pass when it crossed over IPv4 and over IPv6, fail when it crossed over neither " +
		"(one family alone is partial, which only a row that varies may be; anywhere else the run fails and this file is not written). Every cell is probed. " +
		"The `(control)` rows are not transports: they show that plain TCP and HTTPS on the underlay cross the censor, and that the censor sees them. " +
		"The `(reference)` rows are real WireGuard and OpenVPN, which the fingerprint modules must block, " +
		"random-tcp, a naive echo server fed random bytes (what a fully encrypted proxy looks like), which fully-encrypted and the prober must block, " +
		"and relay-tcp, an entry that splices every connection to the camouflage site as REALITY does with what it doesn't recognize, which the prober's upstream tell must block. " +
		"A cell of the active prober or server-hello quotes the module's verdict on the row's first connection to server-1. " +
		"A cell whose detail says `varies` is chance by nature, and says why: it shows what this run got, and only a `(reference)` row may vary.\n\n")
	b.WriteString("| transport | censor | result | detail |\n|---|---|---|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.transport, c.censor, c.result, strings.ReplaceAll(c.detail, "|", `\|`))
	}
	if err := os.WriteFile(filepath.Join(root, "lab", "RESULTS.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
