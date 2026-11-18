//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// TestCensorMatrix scores every transport against every censor module (PRD
// C4, success metric 1) and regenerates lab/RESULTS.md. Each transport's
// row runs in one lab of its own (router, device-a, server-1 and
// camouflage, holding its own lab slot, lab.StartOwnSlot), the rows in
// parallel and a row's cells one after another: a transport passes when
// its data crossed the censor in the lab router over IPv4 and over IPv6,
// fails when it crossed over neither, and is partial when only one family
// crossed, which only a row that varies (censorCase.varies) may be. A cell
// whose outcome contradicts what its censor means to produce fails the
// test, and a cell whose censor can't be trusted (censord died, the kernel
// dropped queued packets, an active module missed a snapshot, the verdict
// log doesn't show the probe's flows, the module the cell quotes didn't
// compare what it must) is an error. RESULTS.md is written only by a
// complete run with no error.
//
// Every cell sets its transport up afresh, and after it the row's lab is
// reset to the state it came up in (matrixRow.reset): the cell's
// processes, censord with them, stopped, the links, addresses, routes,
// policy rules, tables and files it left removed, the router's censor
// table and conntrack cleared, the verdict log gone. A reset that didn't hold makes the cell
// an error, and every later cell of its row.
//
// A transport's off cell (no censor) runs first and the censored cells
// read its result: a transport must pass without a censor before it is
// judged against one. A censored cell without a passing off cell is an
// error and fails fast, whether the off cell didn't run (a -run filter can
// select the cell alone) or it failed.
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

	// runCell probes one cell, resets the row's lab after it, and records
	// it: t.Fatal below ends the function before its return, the cleanup
	// is what survives.
	runCell := func(t *testing.T, row *matrixRow, tr transport, cc censorCase) matrixCell {
		cell := &matrixCell{transport: tr.name, censor: cc.name, result: "error"}
		// Registered first, so it runs after the cleanups that stop the
		// cell's processes.
		t.Cleanup(func() {
			if err := row.reset(); err != nil {
				cell.result, cell.detail = "error", "the lab's reset after the cell didn't hold"
				t.Errorf("%s against %s: %s: %v", tr.name, cc.name, cell.detail, err)
			}
			record(*cell)
		})

		l := row.lab
		target, err := tr.setup(t, l)
		if err != nil {
			cell.detail = "setup failed"
			t.Fatal(err)
		}
		var c *censorRun
		if cc.modules != nil {
			modules, err := withRowSettings(cc.modules(t, l), tr.moduleSettings)
			if err != nil {
				cell.detail = "bad module settings"
				t.Fatal(err)
			}
			c = startCensor(t, l, modules)
		}

		want := cc.want(tr.name)
		budget := probeBudget{pass: want == "pass"}
		if want == "fail" && c != nil {
			budget.watch = c.watchBlocked(t, l, cc.blocker, tr.oneUnderlay)
		}
		held := cc.hold > 0 && tr.hold != nil
		if held {
			tr.hold(t, l, target, cc.hold, cc.idle)
		}
		if cc.settle {
			// An active module judges a connection after it has crossed:
			// the first probe shows it the transport, the cell is the
			// probe after its verdicts. A cell that should not cross
			// may stop on the censor's verdict here too (realityUp's
			// once keeps the first budget).
			tr.probe(t, l, target, probeBudget{watch: budget.watch})
			if err := c.settled(t, l); err != nil {
				cell.result, cell.detail = "error", "the active modules didn't settle"
				t.Fatal(err)
			}
		}
		got := tr.probe(t, l, target, budget)
		cell.result, cell.detail = score(got)
		if held {
			// The probe after the hold crosses on a redialled connection
			// even if the censor cut the one it held: what it blocked
			// during the hold is the cell's verdict.
			how, err := blockedBy(t, l, c, cc.watch, crossed{}, true)
			if err == nil {
				cell.result, cell.detail = "fail", fmt.Sprintf("the censor %s the connection %s for %v: %s", how, cc.heldHow(), cc.hold, c.blockReason(t, cc.watch))
			} else if cell.result == "pass" {
				cell.detail = strings.TrimPrefix(fmt.Sprintf("%s; %s %v first", cell.detail, cc.heldHow(), cc.hold), "; ")
			}
			if cc.trace != "" {
				t.Logf("%s's trace of the connection %s for %v:\n%s", cc.watch, cc.heldHow(), cc.hold, c.traceSummary(t, cc.trace, tr.name+" - "+cc.name))
			}
			if err := judgedFromTheStart(t, l, c, cc.watch); err != nil {
				cell.result, cell.detail = "error", "the censor didn't frame the held connection"
				t.Fatal(err)
			}
		}

		if c != nil {
			if err := c.healthy(t); err != nil {
				cell.result, cell.detail = "error", "censor unhealthy"
				t.Fatal(err)
			}
			if err := tr.sawFlows(t, l, c); err != nil {
				cell.result, cell.detail = "error", "the verdict log misses the probe's flows"
				t.Fatal(err)
			}
			// Evidence only, the score doesn't read it (TP-250 may).
			if passed, err := c.acceptedFor(); err != nil {
				t.Logf("%s against %s: reading the accepts with a reason: %v", tr.name, cc.name, err)
			} else if len(passed) > 0 {
				t.Logf("%s against %s: accepted with a reason: %s", tr.name, cc.name, strings.Join(passed, "; "))
			}
		}
		if want == "fail" || want == "varies" && cell.result != "pass" {
			how, err := blockedBy(t, l, c, cc.blocker, got, tr.oneUnderlay)
			if err != nil {
				t.Error(err)
			} else if cell.result != "pass" && how != "" {
				// how is "" when the probe after a hold crossed: what the
				// hold's connection met is already in the detail.
				cell.detail += "; the censor " + how + " them"
			}
		}
		if k, ok := cc.accepted[tr.name]; ok && cell.result == "fail" {
			reasons, err := c.blockReasons(cc.blocker)
			if err == nil {
				err = k.covers(reasons)
			}
			if err != nil {
				cell.result, cell.detail = "error", fmt.Sprintf("%s; %v", cell.detail, err)
				t.Fatalf("%s against %s: %v", tr.name, cc.name, err)
			}
			cell.detail += "; known, accepted: " + k.why
		}
		if want == "varies" {
			cell.detail = strings.TrimPrefix(cell.detail+"; varies: "+cc.varies[tr.name], "; ")
			want = cell.result
		}
		if cc.report != "" {
			flags, err := c.judged(l, cc.report)
			if err != nil {
				cell.result, cell.detail = "error", "the report module didn't judge the probe's flows"
				t.Fatalf("%s against %s: %v", tr.name, cc.name, err)
			}
			if len(flags) > 0 {
				cell.detail = strings.TrimPrefix(cell.detail+"; "+cc.report+": "+flags[0].why, "; ")
			}
			if err := cc.verdictMisses(tr.name, flags, tr.oneUnderlay); err != nil {
				cell.result, cell.detail = "error", err.Error()
				t.Fatalf("%s against %s: %v", tr.name, cc.name, err)
			}
			if why, ok := unjudged(flags); ok && cell.result == "pass" {
				cell.result = "not judged"
				if why != flags[0].why {
					cell.detail += "; " + cc.report + ": " + why
				}
				if want == "pass" {
					want = cell.result
				}
			}
		}
		if cell.result != want {
			t.Errorf("%s against %s: %s (%s), want %s", tr.name, cc.name, cell.result, cell.detail, want)
		} else {
			t.Logf("%s against %s: %s (%s)", tr.name, cc.name, cell.result, cell.detail)
		}
		return *cell
	}

	if err := checkMatrix(censorCases, transports); err != nil {
		t.Fatal(err)
	}
	off, censored := censorCases[0], censorCases[1:]
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			row := startRow(t)
			offResult := "" // the off cell's result; "" when it didn't run
			t.Run(off.name, func(t *testing.T) {
				// runCell records the cell even when t.Fatal stops it,
				// but the assignment would not happen: claim that the
				// cell ran before it can fail.
				offResult = "error"
				offResult = runCell(t, row, tr, off).result
			})
			for _, cc := range censored {
				t.Run(cc.name, func(t *testing.T) {
					gate := ""
					switch {
					case offResult == "":
						gate = gateNotRun
					case offResult != "pass":
						gate = gateNotPassed
					case row.broken != nil:
						gate = row.broken.Error()
					}
					if gate != "" {
						record(matrixCell{transport: tr.name, censor: cc.name, result: "error", detail: gate})
						t.Fatal(gate)
					}
					runCell(t, row, tr, cc)
				})
			}
		})
	}
}

// checkMatrix refuses cases and rows that would let a cell pass without
// meaning it.
func checkMatrix(cases []censorCase, rows []transport) error {
	if len(cases) == 0 || cases[0].modules != nil {
		return fmt.Errorf("the first censor case is the off cell and must have no censor")
	}
	for _, tr := range rows {
		for module := range tr.moduleSettings {
			if !censor.Registered(module) {
				return fmt.Errorf("%s sets settings of %q, which is no censor module", tr.name, module)
			}
		}
	}
	for _, cc := range cases[1:] {
		if cc.modules == nil {
			return fmt.Errorf("censor case %q has no censor: only the first case may be off", cc.name)
		}
		for tr, want := range cc.expect {
			if want == "fail" && cc.blocker == "" {
				return fmt.Errorf("censor case %q expects %s to fail but names no blocker", cc.name, tr)
			}
		}
		if len(cc.varies) > 0 && cc.blocker == "" {
			return fmt.Errorf("censor case %q has rows that vary but names no blocker", cc.name)
		}
		for tr := range cc.varies {
			if !strings.HasSuffix(tr, " (reference)") {
				return fmt.Errorf("censor case %q lets %s vary: only a reference row may, a gate row's result is never chance", cc.name, tr)
			}
		}
		for tr, k := range cc.accepted {
			if cc.expect[tr] != "fail" {
				return fmt.Errorf("censor case %q accepts %s's fail, but doesn't expect it to fail", cc.name, tr)
			}
			if len(k.reasons) == 0 {
				return fmt.Errorf("censor case %q accepts %s's fail, but names no block reason it accepts it for", cc.name, tr)
			}
		}
		if len(cc.verdictSays) > 0 && cc.report == "" {
			return fmt.Errorf("censor case %q checks verdicts but names no module to report", cc.name)
		}
		// udp shows WireGuard's timing untouched: a held row's pass means
		// something only if the same hold catches udp.
		if cc.hold > 0 {
			i := slices.IndexFunc(rows, func(tr transport) bool { return tr.name == rowUDP })
			if i < 0 || rows[i].hold == nil || cc.expect[rowUDP] != "fail" {
				return fmt.Errorf("censor case %q holds tunnels, but %s, the control, isn't a row held and expected to fail", cc.name, rowUDP)
			}
		}
		for _, tr := range rows {
			if _, tuned := tr.moduleSettings[cc.report]; tuned && cc.report != "" && cc.verdictSays[tr.name] == "" {
				return fmt.Errorf("%s sets %s's settings, but censor case %q doesn't say what its verdict must say (verdictSays)", tr.name, cc.report, cc.name)
			}
			// The prober probes a TCP connection only once its client's
			// first bytes settle: unlisted, a gate row's cell would pass
			// unprobed.
			if cc.report == "prober" && !tr.udp && !isReferenceOrControl(tr.name) && cc.verdictSays[tr.name] == "" {
				return fmt.Errorf("%s is a TCP gate row, but censor case %q doesn't say what the prober's verdict on it must say (verdictSays)", tr.name, cc.name)
			}
			// The comparison needs the site's answer: unlisted, a TLS gate
			// row whose site dial timed out ("not compared") would pass.
			if cc.report == "server-hello" && tr.tls && !isReferenceOrControl(tr.name) && cc.verdictSays[tr.name] == "" {
				return fmt.Errorf("%s is a TLS gate row, but censor case %q doesn't say what the server-hello verdict on it must say (verdictSays)", tr.name, cc.name)
			}
		}
	}
	return nil
}

// isReferenceOrControl says whether a row is no thinkpol transport, by
// its name's suffix: every other row is a gate row.
func isReferenceOrControl(row string) bool {
	return strings.HasSuffix(row, " (reference)") || strings.HasSuffix(row, " (control)")
}

// TestCheckMatrix: the matrix as written passes its own checks; a TCP
// gate row missing from the prober case's verdictSays, a TLS gate row
// missing from the server-hello case's, a row tuning a report module
// without a verdictSays entry, a row tuning a module that doesn't exist,
// a held case without udp held and expected to fail (the control), an
// accepted fail the case doesn't expect, and one that names no block
// reason each fail the run.
func TestCheckMatrix(t *testing.T) {
	if err := checkMatrix(censorCases, transports); err != nil {
		t.Fatalf("the matrix: %v", err)
	}
	on := func(*testing.T, *lab.Lab) []censor.ModuleConfig { return nil }
	prober := censorCase{name: "active prober", modules: on, report: "prober", verdictSays: map[string]string{"gate-a": "TLS: the server", "tls-gate": "TLS: the server"}}
	serverHello := censorCase{name: "server-hello", modules: on, report: "server-hello", verdictSays: map[string]string{"tls-gate": "server hello matches the site"}}
	cases := []censorCase{{name: "off"}, prober, serverHello}
	for _, c := range []struct {
		name    string
		rows    []transport
		wantErr string
	}{
		{"listed TCP gate row, rows that aren't gate rows", []transport{{name: "gate-a"}, {name: "udp-gate", udp: true}, {name: rowRandomTCP}, {name: rowHTTPS}}, ""},
		{"unlisted TCP gate row", []transport{{name: "gate-b"}}, "gate-b is a TCP gate row"},
		{"tuned, unlisted", []transport{{name: "udp-gate", udp: true, moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}}}}, "doesn't say what its verdict must say"},
		{"tuned reference row, unlisted", []transport{{name: rowRelayTCP, moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}}}}, "doesn't say what its verdict must say"},
		{"tuned, listed", []transport{{name: "gate-a", moduleSettings: map[string]map[string]any{"prober": {"upstreamTell": "report"}}}}, ""},
		{"misspelt module", []transport{{name: "gate-a", moduleSettings: map[string]map[string]any{"probr": {"upstreamTell": "report"}}}}, "no censor module"},
		{"listed TLS gate row, TLS rows that aren't gate rows", []transport{{name: "tls-gate", tls: true}, {name: rowHTTPS, tls: true}, {name: rowRelayTCP, tls: true}}, ""},
		{"unlisted TLS gate row", []transport{{name: "gate-a", tls: true}}, "gate-a is a TLS gate row"},
	} {
		err := checkMatrix(cases, c.rows)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: %v, want an error saying %q", c.name, err, c.wantErr)
		}
	}
	// A held case must catch the control: udp held and expected to fail.
	held := func(expect map[string]string) []censorCase {
		return []censorCase{{name: "off"}, {name: "held", modules: on, hold: time.Minute, expect: expect, blocker: "wireguard-rhythm"}}
	}
	hold := func(*testing.T, *lab.Lab, probeTarget, time.Duration, bool) {}
	for _, c := range []struct {
		name    string
		cases   []censorCase
		rows    []transport
		wantErr bool
	}{
		{"control held, expected to fail", held(map[string]string{rowUDP: "fail"}), []transport{{name: rowUDP, udp: true, hold: hold}}, false},
		{"control expected to pass", held(nil), []transport{{name: rowUDP, udp: true, hold: hold}}, true},
		{"control not held", held(map[string]string{rowUDP: "fail"}), []transport{{name: rowUDP, udp: true}}, true},
		{"no control row", held(map[string]string{rowUDP: "fail"}), []transport{{name: rowReality, hold: hold}}, true},
	} {
		if err := checkMatrix(c.cases, c.rows); (err != nil) != c.wantErr {
			t.Errorf("%s: %v, want an error %v", c.name, err, c.wantErr)
		}
	}
	// An accepted fail is an expected fail, nothing else.
	accepting := censorCase{name: "accepting", modules: on, blocker: "wireguard-rhythm",
		expect: map[string]string{rowReality: "fail"}, accepted: map[string]knownTell{rowReality: {why: "a known tell", reasons: []string{censor.WGRhythmByBurst}}}}
	if err := checkMatrix([]censorCase{{name: "off"}, accepting}, nil); err != nil {
		t.Errorf("an accepted, expected fail: %v", err)
	}
	accepting.accepted = map[string]knownTell{rowReality: {why: "a known tell"}}
	if err := checkMatrix([]censorCase{{name: "off"}, accepting}, nil); err == nil {
		t.Error("an accepted fail that names no block reason passed the checks")
	}
	accepting.accepted = map[string]knownTell{rowReality: {why: "a known tell", reasons: []string{censor.WGRhythmByBurst}}}
	accepting.expect = nil
	if err := checkMatrix([]censorCase{{name: "off"}, accepting}, nil); err == nil {
		t.Error("an accepted fail the case doesn't expect passed the checks")
	}
}

// TestKnownTellCovers: reality's accepted rhythm fail covers blocks by the
// count and burst signals only. A block for a size or quiet tell (the
// rekey signal's reason, keepalives), beside them or alone, or no block
// reason at all, is news: an error that names the reason.
func TestKnownTellCovers(t *testing.T) {
	k := rhythmCase("wireguard-rhythm", false).accepted[rowReality]
	const (
		burst     = "WireGuard rekey by burst: 3 records one way and 2 the other within 10ms, 3 times, the last 2m0s apart"
		count     = "WireGuard rekey by record count: the difference each way stepped 3 times by +1, the last 2m0s apart, flat in between"
		sizes     = "WireGuard rekey: records of 167 and 111 bytes exchanged 3 times, the last 2m0s apart"
		keepalive = "WireGuard keepalives: 3 idle records of 507 bytes, 25s apart"
	)
	for _, c := range []struct {
		name    string
		reasons []string
		bad     string // the reason the error must name; "" when covered
	}{
		{"burst", []string{burst}, ""},
		{"count", []string{count}, ""},
		{"both counting signals", []string{count, burst}, ""},
		{"sizes", []string{sizes}, sizes},
		{"keepalives", []string{keepalive}, keepalive},
		{"a burst and keepalives", []string{burst, keepalive}, keepalive},
		{"no reason", nil, "no block reason"},
	} {
		err := k.covers(c.reasons)
		switch {
		case c.bad == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s: %v, want an error naming %q", c.name, err, c.bad)
		}
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
	// hold keeps the tunnel of a row with a hold up this long before the
	// probe, in use or, with idle, idle after one ping, and the cell fails
	// if watch, a module of the case, blocked its connection meanwhile.
	// trace is the path watch writes its trace to, which the cell logs a
	// summary of.
	hold  time.Duration
	idle  bool
	watch string
	trace string
	// accepted holds the rows expected to fail on a tell the design
	// accepts: a failing cell's detail says so, so the fail reads as
	// known, never as news, and stays a correct cell like any expected
	// fail, as long as the blocker blocked for that tell alone.
	accepted map[string]knownTell
	// settle probes twice, the cell scoring the second, once the active
	// modules have flagged every flow of server-1 a module tagged.
	settle bool
	// report names the module whose flags of connections between device-a
	// and server-1 the cell checks (verdictSays), its detail quoting the
	// first.
	report string
	// verdictSays holds the rows whose report verdicts must say something,
	// the comparison the cell is for: every flag the module raised on the
	// row's connections must say it, and each family the row's probe uses
	// needs one. A verdict without it ("not compared", another reason) or
	// a family with no flag is an error, never a pass: the IPv4
	// connection's match says nothing of the IPv6 one's.
	verdictSays map[string]string
}

// knownTell is a tell the design accepts: what shows and the residual
// risk that accepts it (why), and the starts of the blocker's reasons it
// is (reasons).
type knownTell struct {
	why     string
	reasons []string
}

// covers is an error unless every reason the blocker blocked for is the
// tell's: a block for anything else is news, never the known fail.
func (k knownTell) covers(reasons []string) error {
	if len(reasons) == 0 {
		return errors.New("the blocker logged no block reason: not the known tell")
	}
	for _, r := range reasons {
		if !slices.ContainsFunc(k.reasons, func(p string) bool { return strings.HasPrefix(r, p) }) {
			return fmt.Errorf("blocked for %q, not the known tell (%s)", r, strings.Join(k.reasons, " or "))
		}
	}
	return nil
}

// unjudged finds a flag that couldn't judge what its cell is for: the
// prober's upstream tell, unattributable. Such a cell is "not judged",
// never a pass.
func unjudged(flags []judgment) (string, bool) {
	for _, f := range flags {
		if strings.Contains(f.why, "upstream tell: unattributable") {
			return f.why, true
		}
	}
	return "", false
}

// TestUnjudged: a flag whose upstream tell is unattributable, on either
// family, makes the cell not judged; a tell shown or absent doesn't.
func TestUnjudged(t *testing.T) {
	const (
		shown  = "accept, server 192.0.2.9:443 answers like the reference: upstream tell: a connection from 192.0.2.9 to the reference during every probe (7 of 7; 8 dials in 4s of probes, 1 in 30s outside them), reported, not flagged"
		unsure = "accept, server [2001:db8::9]:443 answers like the reference: upstream tell: unattributable (8 dials in 4s of probes, 30 in 30s outside them, at least half the rate; a connection from 2001:db8::9 to the reference during 7 of 7 probes)"
		absent = "accept, server 192.0.2.9:443 answers like the reference: connections to the reference during 0 of 7 probes"
	)
	for _, c := range []struct {
		name  string
		flags []judgment
		want  bool
	}{
		{"shown", []judgment{{true, shown}}, false},
		{"absent", []judgment{{true, absent}}, false},
		{"unattributable on IPv6", []judgment{{true, shown}, {false, unsure}}, true},
		{"no flag", nil, false},
	} {
		if why, ok := unjudged(c.flags); ok != c.want || ok && why != unsure {
			t.Errorf("%s: %q, %v, want %v", c.name, why, ok, c.want)
		}
	}
}

// heldHow says how the case held the tunnel.
func (cc censorCase) heldHow() string {
	if cc.idle {
		return "held idle"
	}
	return "held in use"
}

// judgment is a flag of the report module on a connection between
// device-a and server-1: its family, and "<verdict>, <reason>".
type judgment struct {
	v4  bool
	why string
}

// verdictMisses is an error when row's flags from the report module lack
// what the case needs them to say: a flag that doesn't say it, or says
// "not compared", or a family with no flag (either family will do for a
// row whose tunnels share one underlay family). The module didn't compare
// what the cell is for, which must not score as a pass.
func (cc censorCase) verdictMisses(row string, flags []judgment, oneUnderlay bool) error {
	says, ok := cc.verdictSays[row]
	if !ok {
		return nil
	}
	flagged := map[bool]bool{}
	for _, f := range flags {
		if strings.Contains(f.why, "not compared") || !strings.Contains(f.why, says) {
			return fmt.Errorf("%s's verdict %q doesn't say %q", cc.report, f.why, says)
		}
		flagged[f.v4] = true
	}
	switch {
	case len(flagged) == 0:
		return fmt.Errorf("%s never flagged the row's connections, want verdicts saying %q", cc.report, says)
	case oneUnderlay:
		return nil
	case !flagged[true]:
		return fmt.Errorf("%s flagged no IPv4 connection of the row, want a verdict saying %q", cc.report, says)
	case !flagged[false]:
		return fmt.Errorf("%s flagged no IPv6 connection of the row, want a verdict saying %q", cc.report, says)
	}
	return nil
}

// TestVerdictMisses: a cell whose module didn't compare, on any of the
// row's connections ("not compared", or no flag in a family), is an
// error, whatever the row's crossing scored.
func TestVerdictMisses(t *testing.T) {
	const match, unreachable = "accept, server hello matches the site camouflage.example.net", "accept, not compared: the site is unreachable"
	cc := censorCase{report: "server-hello", verdictSays: map[string]string{rowHTTPS: "server hello matches the site"}}
	for _, c := range []struct {
		name        string
		flags       []judgment
		oneUnderlay bool
		wantErr     bool
	}{
		{"both families match", []judgment{{true, match}, {false, match}, {true, match}}, false, false},
		{"no flag", nil, false, true},
		{"IPv6 not compared after IPv4 matched", []judgment{{true, match}, {false, unreachable}}, false, true},
		{"IPv6 compared later, once not", []judgment{{true, match}, {false, match}, {false, unreachable}}, false, true},
		{"not compared, saying the text too", []judgment{{true, match}, {false, "accept, not compared: server hello matches the site's name only"}}, false, true},
		{"another reason", []judgment{{true, match}, {false, "drop, server hello unlike the site"}}, false, true},
		{"no IPv6 flag", []judgment{{true, match}, {true, match}}, false, true},
		{"no IPv4 flag", []judgment{{false, match}}, false, true},
		{"one underlay, one family", []judgment{{false, match}}, true, false},
	} {
		if err := cc.verdictMisses(rowHTTPS, c.flags, c.oneUnderlay); (err != nil) != c.wantErr {
			t.Errorf("%s: %v, want an error: %v", c.name, err, c.wantErr)
		}
	}
	if err := cc.verdictMisses(rowPlainTCP, nil, false); err != nil {
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
	// no site; the relay's clients name the site it relays to, and so do
	// reality's, whose server-1 also checks its target under that name:
	// a censor blocking the site's name blocks reality with it.
	{name: "sni-blocklist (entry)", expect: map[string]string{rowHTTPS: "fail", rowRelayTCP: "fail", rowReality: "fail"}, blocker: "sni-blocklist",
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
	// M2 gate checks (docs/design/milestones.md). A transport's pass means
	// something only when its tunnel runs long enough for the rhythm to
	// show: three rekeys (up to 7 minutes, up to about 10 minutes when
	// batched), or three idle keepalives. So reality, which doesn't batch,
	// and udp, the control (WireGuard's timing untouched), hold their
	// tunnels for 7.5 minutes first, in use (a ping every 2 s), with the
	// module's default settings; udp must be caught for the case to mean
	// anything. reality is caught too, by counting its records each way: a
	// known tell, accepted in RR65 until cover records go both ways (owner,
	// 2026-11-16). The other rows aren't held, and pass. The idle case,
	// rhythmCase("wireguard-rhythm (idle)", true), is out of the matrix
	// until TP-080 (liveness rides on data, idle path probes back off)
	// brings it back: an idle thinkpol tunnel sends no WireGuard rhythm,
	// so udp can't be caught there, and thinkpol's path probes are the
	// idle tell (TP-223's Notes).
	rhythmCase("wireguard-rhythm", false),
	// M2 gate checks (docs/design/milestones.md). Wu et al.'s exemptions
	// on each connection's first data, UDP's first datagram too, and
	// residual censorship after a block: thinkpol's udp sends random bytes
	// first (exempt by chance: six printable bytes first, about once in
	// 400 tunnels, or more than half printable, about once in 175 84-byte
	// datagrams, which residual censorship leaves one judgement per
	// 3-tuple and residual window, a link's first connection over each
	// underlay family); OpenVPN's first packet is
	// mostly zeros, and HTTPS starts with a TLS record. A WireGuard
	// initiation ends in 16 zero bytes, and is exempt about one time in
	// four.
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
	// answers, and shows the upstream tell. So does reality, which splices
	// every probe to its target; its tell is reported, not flagged (owner,
	// 2026-11-09: REALITY's design can't avoid it), and its verdict must
	// judge the tell: shown on every probe (n of n), or unattributable
	// when server-1 dialed the site outside the probes at half their rate
	// or more (device-a's own connections make it dial), which scores the
	// cell not judged, never a pass. reality's target is one IPv4 address, so
	// a link over IPv6 dials it from server-1's IPv4 address: the prober
	// is told server-1's two addresses are one host, as a censor that
	// knows them would (RR31), so the tell shows over either family.
	{name: "active prober", expect: map[string]string{rowRandomTCP: "fail", rowOpenVPNTCP: "fail", rowRelayTCP: "fail"}, blocker: "prober",
		settle: true, report: "prober",
		verdictSays: map[string]string{rowHTTPS: "TLS: the server", rowRelayTCP: "upstream tell: a connection", rowReality: "upstream tell: "},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			camouflage := lab.StartCamouflage(t, l)
			return []censor.ModuleConfig{
				{Name: "fully-encrypted", Settings: json.RawMessage(`{"tagOnly": true}`)},
				{Name: "prober", Settings: withServerHost(t, l, proberSettings(t, l, camouflage))},
			}
		}},
	// The https, relay and reality rows' ClientHellos name the camouflage
	// site: their server hellos are compared with the site's answer to the
	// same ClientHello (the relay's is the site's own, reality's REALITY's
	// imitation of it).
	{name: "server-hello", settle: true, report: "server-hello",
		verdictSays: map[string]string{rowHTTPS: "server hello matches the site", rowRelayTCP: "server hello matches the site", rowReality: "server hello matches the site"},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			camouflage := lab.StartCamouflage(t, l)
			b, err := json.Marshal(map[string]map[string]string{"sites": {httpsName: camouflage[0].String()}})
			if err != nil {
				t.Fatal(err)
			}
			return []censor.ModuleConfig{{Name: "server-hello", Settings: b}}
		}},
}

// rhythmTrace is where the rhythm cases' module writes its trace, in the
// router.
const rhythmTrace = "/run/censor/rhythm.jsonl"

// realityRhythmCounted is why reality's fail of the rhythm case is known
// (lab/censor/doc.go, TP-223).
const realityRhythmCounted = "each rekey leaves one more record from the device than from the server, " +
	"counted each way and in a burst of 3 against 2 every 2 minutes: the floor hides sizes, not counts; " +
	"RR65 accepts it until cover records go both ways"

// rhythmCase is the wireguard-rhythm case that holds the held rows'
// tunnels in use, or idle. reality's fail is a known tell: its cell says
// so.
func rhythmCase(name string, idle bool) censorCase {
	return censorCase{name: name, hold: 450 * time.Second, idle: idle, watch: "wireguard-rhythm", trace: rhythmTrace,
		expect: map[string]string{rowUDP: "fail", rowReality: "fail"}, blocker: "wireguard-rhythm",
		accepted: map[string]knownTell{rowReality: {why: realityRhythmCounted, reasons: []string{censor.WGRhythmByCount, censor.WGRhythmByBurst}}},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "wireguard-rhythm", Settings: json.RawMessage(`{"trace": "` + rhythmTrace + `"}`)}}
		}}
}

// withServerHost adds to the prober's settings that server-1's addresses
// are one host.
func withServerHost(t *testing.T, l *lab.Lab, settings json.RawMessage) json.RawMessage {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal(settings, &s); err != nil {
		t.Fatal(err)
	}
	server := l.Node(lab.Server1)
	s["hosts"] = [][]string{{server.IPv4(lab.NetServers).String(), server.IPv6(lab.NetServers).String()}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
	// probe reports whether data crossed over each family, retrying each
	// as its budget says.
	probe func(t *testing.T, l *lab.Lab, to probeTarget, b probeBudget) crossed
	// sawFlows checks the verdict log has the probe's flows on the
	// underlay: the censor saw what it judged.
	sawFlows func(t *testing.T, l *lab.Lab, c *censorRun) error
	// udp: the row's underlay is UDP, which the prober never probes.
	udp bool
	// oneUnderlay: both overlay families ride one underlay family, so a
	// blocked cell may blame either family's underlay.
	oneUnderlay bool
	// moduleSettings overrides, by module name, settings of the censor
	// modules a case runs, in every cell of the row: a key set here
	// replaces the case's. A gate row whose entry relays what it doesn't
	// recognize to the camouflage site (REALITY) asks for the prober's
	// upstreamTell "report" here. A key that names no module fails the
	// run, and so does a row tuning a case's report module without being
	// in its verdictSays (checkMatrix).
	moduleSettings map[string]map[string]any
	// tls: the row's underlay connection is TLS whose ClientHello names
	// the camouflage site, so the server-hello comparison has something
	// to compare (checkMatrix).
	tls bool
	// hold, if set, keeps the transport up for a while (a case's hold)
	// before the probe: in use, or idle.
	hold func(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool)
}

// withRowSettings is the case's module configs with a row's overrides
// (transport.moduleSettings) merged in.
func withRowSettings(configs []censor.ModuleConfig, overrides map[string]map[string]any) ([]censor.ModuleConfig, error) {
	out := slices.Clone(configs)
	for i, mc := range out {
		o, ok := overrides[mc.Name]
		if !ok {
			continue
		}
		settings := map[string]any{}
		if len(mc.Settings) > 0 {
			if err := json.Unmarshal(mc.Settings, &settings); err != nil {
				return nil, fmt.Errorf("%s's settings: %w", mc.Name, err)
			}
		}
		maps.Copy(settings, o)
		b, err := json.Marshal(settings)
		if err != nil {
			return nil, fmt.Errorf("%s's settings: %w", mc.Name, err)
		}
		out[i].Settings = b
	}
	return out, nil
}

// TestWithRowSettings: a row's override reaches the module it names, and
// only that one; a row without one (relay-tcp, whose cell fails on the
// upstream tell) runs the case's settings.
func TestWithRowSettings(t *testing.T) {
	proberSettings := `{"reference": {"name": "camouflage.example.net", "addresses": ["198.51.100.10:443"]}, "destinations": ["192.0.2.9"]}`
	configs := []censor.ModuleConfig{
		{Name: "fully-encrypted", Settings: json.RawMessage(`{"tagOnly": true}`)},
		{Name: "prober", Settings: json.RawMessage(proberSettings)},
	}
	got, err := withRowSettings(configs, map[string]map[string]any{"prober": {"upstreamTell": "report"}})
	if err != nil {
		t.Fatal(err)
	}
	var prober struct {
		Reference    struct{ Name string } `json:"reference"`
		Destinations []string              `json:"destinations"`
		UpstreamTell string                `json:"upstreamTell"`
	}
	if err := json.Unmarshal(got[1].Settings, &prober); err != nil {
		t.Fatal(err)
	}
	if prober.UpstreamTell != "report" || prober.Reference.Name != "camouflage.example.net" || len(prober.Destinations) != 1 {
		t.Errorf("the prober's settings with the row's override: %s", got[1].Settings)
	}
	if string(got[0].Settings) != `{"tagOnly": true}` || string(configs[1].Settings) != proberSettings {
		t.Errorf("touched what the override doesn't name: %s, the case's own %s", got[0].Settings, configs[1].Settings)
	}
	if _, _, err := censor.Build(censor.Config{Modules: got}); err != nil {
		t.Errorf("the merged settings: %v", err)
	}
	// The override is what the module parses: a value it refuses fails.
	bad, err := withRowSettings(configs, map[string]map[string]any{"prober": {"upstreamTell": "ignore"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := censor.Build(censor.Config{Modules: bad}); err == nil {
		t.Error("the module accepted upstreamTell \"ignore\": the override didn't reach it")
	}
	unchanged, err := withRowSettings(configs, nil)
	if err != nil || string(unchanged[1].Settings) != proberSettings {
		t.Errorf("a row without overrides: %s, %v", unchanged[1].Settings, err)
	}
	for _, tr := range transports {
		if _, ok := tr.moduleSettings["prober"]["upstreamTell"]; ok && tr.name == rowRelayTCP {
			t.Errorf("%s sets the prober's upstreamTell: its cell must fail on the tell", tr.name)
		}
	}
}

// transports is the matrix's rows, longest first: go test starts parallel
// rows in this order as slots free up, so the rows that hold their tunnel
// 7.5 minutes for wireguard-rhythm (reality about 865 s, udp) never wait
// behind short ones, and the matrix takes about as long as its longest row
// (RESULTS.md sorts the rows by name).
var transports = []transport{
	realityRow,
	{name: rowUDP, setup: setupUDP, probe: probeUDP, sawFlows: sawUDP, udp: true, oneUnderlay: true, hold: holdTunnel},
	{name: rowPlainTCP, setup: setupPlainTCP, probe: probePlainTCP, sawFlows: sawPlainTCP},
	{name: rowHTTPS, setup: setupHTTPS, probe: probeHTTPSOn(443), sawFlows: sawHTTPS, tls: true},
	{name: rowWireGuard, setup: setupWireGuard, probe: probeUDP, sawFlows: sawWireGuard, udp: true},
	{name: rowOpenVPNUDP, setup: openVPN{"udp"}.setup, probe: openVPN{"udp"}.probe, sawFlows: openVPN{"udp"}.sawFlows, udp: true},
	{name: rowOpenVPNTCP, setup: openVPN{"tcp"}.setup, probe: openVPN{"tcp"}.probe, sawFlows: openVPN{"tcp"}.sawFlows},
	{name: rowRandomTCP, setup: setupRandom, probe: probeRandom, sawFlows: sawRandom},
	{name: rowRelayTCP, setup: setupRelay, probe: probeHTTPSOn(relayRowPort), sawFlows: sawRelay, tls: true},
}

// probeWindow is how long a probe retries a family that should cross; one
// that should not gets blockedWindow, unless its budget's watch says
// sooner that the censor blocked an attempt.
const probeWindow, blockedWindow = 30 * time.Second, 8 * time.Second

// probeBudget is how a probe retries each family: for probeWindow when
// the cell should cross (pass), else for blockedWindow, or, with watch,
// until an attempt failed that the censor blocked.
type probeBudget struct {
	pass  bool
	watch *blockWatch
}

// blockWatch tells whether the censor blocked one attempt of a probe, by
// the verdict log's lines written while it ran.
type blockWatch struct {
	// read is the verdict log caught up with the queue (censorRun.caughtUp):
	// every packet queued before the call has its decisions in it.
	read func() string
	// blocked says whether one attempt's lines show its family (v6)
	// blocked (attemptBlocked).
	blocked func(lines string, v6 bool) bool
}

// retry runs attempt for one family (v6) until it says yes or the budget
// says no (untilAnswerOr).
func (b probeBudget) retry(v6 bool, attempt func() (bool, error)) (bool, error) {
	within := blockedWindow
	if b.pass {
		within = probeWindow
	}
	if b.watch == nil {
		return untilAnswerOr(within, nil, attempt)
	}
	return untilAnswerOr(within, b.watch.attempts(v6), attempt)
}

// attempts is untilAnswerOr's watch for one family (v6): before each
// attempt it marks the caught-up log's end, after a failed one it reads
// the log caught up again and judges only the lines past the mark:
// decisions on packets queued while the attempt ran. What an earlier
// attempt, the settle probe or a hold left in the log doesn't count. The
// mark is read again before each attempt, not taken from the last
// attempt's read: a late packet of that attempt decided during the pause
// between them would count toward the next.
func (w *blockWatch) attempts(v6 bool) func() func() bool {
	return func() func() bool {
		mark := len(w.read())
		return func() bool {
			log := w.read()
			var lines string
			if len(log) >= mark { // shorter: cleared, nothing to judge
				lines = log[mark:]
			}
			return w.blocked(lines, v6)
		}
	}
}

// watchBlocked is the watch of a cell that should not cross: blocker's
// verdicts on server-1's address of the family a probe tries, or of
// either family on a row whose tunnels share one underlay
// (transport.oneUnderlay), where the cell claims the transport blocked
// whichever family carries it. A failed read fails the test.
func (c *censorRun) watchBlocked(t *testing.T, l *lab.Lab, blocker string, oneUnderlay bool) *blockWatch {
	server := l.Node(lab.Server1)
	v4, v6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)
	return &blockWatch{
		read: func() string {
			log, err := c.caughtUp()
			if err != nil {
				t.Fatal(err)
			}
			return log
		},
		blocked: func(lines string, isV6 bool) bool {
			addrs := []netip.Addr{v4}
			switch {
			case oneUnderlay:
				addrs = append(addrs, v6)
			case isV6:
				addrs = []netip.Addr{v6}
			}
			blocked, err := attemptBlocked(lines, blocker, addrs)
			if err != nil {
				t.Fatal(err)
			}
			return blocked
		},
	}
}

// attemptBlocked says whether one attempt's verdict log lines show it
// blocked: a decision of blocker's dropping or resetting a flow to or
// from addrs, with no accept on that flow after it. The log has one
// decision per flow, verdict and module, so a censor that drops a flow's
// first packet and lets the rest through shows its accept; one that
// accepts, drops, then accepts again shows no second accept, and looks
// blocked.
func attemptBlocked(lines, blocker string, addrs []netip.Addr) (bool, error) {
	blocked := map[censor.FlowKey]bool{}
	_, err := matchVerdicts(lines, func(e verdictLine) bool {
		if e.Event != censor.EventDecision || !slices.Contains(addrs, e.Key.Dst) && !slices.Contains(addrs, e.Key.Src) {
			return false
		}
		switch {
		case e.Module == blocker && (e.Verdict == censor.Drop || e.Verdict == censor.Reset):
			blocked[e.Key] = true
		case e.Verdict == censor.Accept:
			delete(blocked, e.Key)
		}
		return false
	})
	return len(blocked) > 0, err
}

func setupPlainTCP(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server := l.Node(lab.Server1)
	listenTCP(t, server)
	return probeTarget{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

func probePlainTCP(t *testing.T, l *lab.Lab, to probeTarget, b probeBudget) crossed {
	dev := l.Node(lab.DeviceA)
	connects := func(a netip.Addr) func() (bool, error) {
		return func() (bool, error) { return tcpReaches(dev, a, tcpProbePort, 2) }
	}
	return crossed{
		v4: mustProbe(t)(b.retry(false, connects(to.v4))),
		v6: mustProbe(t)(b.retry(true, connects(to.v6))),
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
	space := newM0Space(t, l.Node(lab.Camouflage), server)
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	startUp(t, dev)
	startUp(t, server)
	if _, err := statusWithin(server, 60*time.Second, nil, mapApplied(version)); err != nil {
		return probeTarget{}, err
	}
	if _, err := statusWithin(dev, 60*time.Second, nil, mapApplied(version), linkUp); err != nil {
		return probeTarget{}, err
	}
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// probeUDP pings server-1's overlay addresses, IPv4 and IPv6, through the
// tunnel.
func probeUDP(t *testing.T, l *lab.Lab, to probeTarget, b probeBudget) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: mustProbe(t)(b.retry(false, pingOnce(dev, to.v4, pingNoReply))),
		v6: mustProbe(t)(b.retry(true, pingOnce(dev, to.v6, pingNoReply))),
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
	found := map[censor.Verdict]bool{}
	for _, addrs := range blockedFamilies(server.IPv4(lab.NetServers), server.IPv6(lab.NetServers), got, oneUnderlay) {
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

// blockedFamilies is what blockedBy needs a blocker's verdict on, one
// entry each: server-1's address of each family that didn't cross, or
// either address once for a row whose tunnels share one underlay family.
func blockedFamilies(v4, v6 netip.Addr, got crossed, oneUnderlay bool) [][]netip.Addr {
	if oneUnderlay {
		return [][]netip.Addr{{v4, v6}}
	}
	var families [][]netip.Addr
	if !got.v4 {
		families = append(families, []netip.Addr{v4})
	}
	if !got.v6 {
		families = append(families, []netip.Addr{v6})
	}
	return families
}

// TestBlockedFamilies: a family that didn't cross needs the blocker's
// verdict on its own address, not on either of the server's.
func TestBlockedFamilies(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	for _, c := range []struct {
		got         crossed
		oneUnderlay bool
		want        [][]netip.Addr
	}{
		{crossed{}, false, [][]netip.Addr{{v4}, {v6}}},
		{crossed{v6: true}, false, [][]netip.Addr{{v4}}},
		{crossed{v4: true}, false, [][]netip.Addr{{v6}}},
		{crossed{v4: true, v6: true}, false, nil},
		{crossed{}, true, [][]netip.Addr{{v4, v6}}},
	} {
		got := blockedFamilies(v4, v6, c.got, c.oneUnderlay)
		if !slices.EqualFunc(got, c.want, slices.Equal[[]netip.Addr]) {
			t.Errorf("%+v, one underlay %v: %v, want %v", c.got, c.oneUnderlay, got, c.want)
		}
	}
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

// TestProbeStopsOnItsOwnBlockOnly: a probe that should not cross stops
// early only after a failed attempt during which the blocker dropped or
// reset a flow to or from server-1's address (and didn't accept it
// after); what the log had before the attempt, a late decision on the
// attempt before, another module's drop or the other family's don't stop
// it, and it goes on to the attempt that crosses. The window is counted
// in attempts, so load can't change how many fit.
func TestProbeStopsOnItsOwnBlockOnly(t *testing.T) {
	server4, server6 := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	line := func(sport uint16, dst netip.Addr, module string, v censor.Verdict) string {
		src := netip.MustParseAddr("192.0.2.1")
		if dst.Is6() {
			src = netip.MustParseAddr("2001:db8::1")
		}
		key := censor.FlowKey{Proto: censor.ProtoTCP, Src: src, SrcPort: sport, Dst: dst, DstPort: 443}
		b, err := json.Marshal(censor.LogEntry{Event: censor.EventDecision, Flow: key.String(), Module: module, Verdict: v})
		if err != nil {
			t.Fatal(err)
		}
		return string(b) + "\n"
	}
	drop := func(sport uint16) string { return line(sport, server4, "ip-blocklist", censor.Drop) }
	const window = 5 // attempts
	for _, c := range []struct {
		name string
		// before is the log before the probe; attempts what each attempt
		// adds to it, the last one crossing (if crosses); late what the
		// log gains just after the read that judged attempt i failed.
		before   string
		attempts []string
		late     []string
		crosses  bool
		// tries is how many attempts ran, 0 for "until the window ran
		// out"; failing is the one attempt (1-based) that fails to run.
		tries, failing int
	}{
		{"the blocker dropped the flow's first packet before the probe", drop(1), []string{"", ""}, nil, true, 2, 0},
		{"its packet dropped, then accepted", "", []string{drop(2) + line(2, server4, "", censor.Accept), ""}, nil, true, 2, 0},
		{"its packet dropped", "", []string{drop(3)}, nil, false, 1, 0},
		{"its packet reset", "", []string{line(4, server4, "ip-blocklist", censor.Reset)}, nil, false, 1, 0},
		{"another module's drop", "", []string{line(5, server4, "sni-blocklist", censor.Drop)}, nil, false, 0, 0},
		{"the other family's drop", "", []string{line(6, server6, "ip-blocklist", censor.Drop)}, nil, false, 0, 0},
		{"a drop in an attempt that failed to run", "", []string{drop(7), "", ""}, nil, true, 3, 1},
		{"a drop decided after the attempt was judged", "", []string{"", "", ""}, []string{drop(8)}, true, 3, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			log, late, tries := c.before, "", 0
			w := &blockWatch{
				read: func() string {
					read := log
					log, late = log+late, ""
					return read
				},
				blocked: func(lines string, v6 bool) bool {
					if v6 {
						t.Fatal("asked for IPv6")
					}
					blocked, err := attemptBlocked(lines, "ip-blocklist", []netip.Addr{server4})
					if err != nil {
						t.Fatal(err)
					}
					return blocked
				},
			}
			left := func() (out, gaveUp bool) { return tries >= window, tries >= 2*window }
			crossed, err := answerWhile(left, 0, w.attempts(false), func() (bool, error) {
				tries++
				i := min(tries, len(c.attempts)) - 1
				log += c.attempts[i]
				if tries <= len(c.late) {
					late = c.late[tries-1]
				}
				if tries == c.failing {
					return false, errors.New("docker exec failed")
				}
				return c.crosses && tries == len(c.attempts), nil
			})
			switch {
			case err != nil:
				t.Fatal(err)
			case crossed != c.crosses:
				t.Errorf("crossed %v after %d attempts, want %v", crossed, tries, c.crosses)
			case c.tries > 0 && tries != c.tries:
				t.Errorf("%d attempts, want %d", tries, c.tries)
			case c.tries == 0 && tries != window:
				t.Errorf("stopped after %d attempts, want the window's %d", tries, window)
			}
		})
	}
}

// pingOnce is one ping attempt for a probe's budget: "doesn't cross" is
// a failed ping noReply accepts (pingNoReply: only ping's own "no
// reply"), any other failure an error.
func pingOnce(from *lab.Node, to netip.Addr, noReply func(lab.Result) bool) func() (bool, error) {
	return func() (bool, error) {
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
	}
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

// acceptedFor is every flow a module accepted with a reason (a
// fully-encrypted exemption), as "flow: module: reason", in log order.
func (c *censorRun) acceptedFor() ([]string, error) {
	log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
	if err != nil {
		return nil, fmt.Errorf("reading the verdict log: %w", err)
	}
	var passed []string
	_, err = matchVerdicts(completeLines(log), func(e verdictLine) bool {
		if e.Event == censor.EventDecision && e.Verdict == censor.Accept && e.Module != "" {
			passed = append(passed, fmt.Sprintf("%s: %s: %s", e.Flow, e.Module, e.Reason))
		}
		return false
	})
	return passed, err
}

// verdictLine is a verdict log entry with its flow parsed.
type verdictLine struct {
	censor.LogEntry
	Key censor.FlowKey
}

// logged reports whether a verdict log entry matches once the log has
// caught up with every packet the kernel queued so far (caughtUp): a
// passive module's decisions, and the flags already written. A read that
// fails is retried; the test fails if none succeeds within the bound. A
// whole line that doesn't parse fails the test (censord writes whole
// lines); the part after the last newline is a write in progress, left
// for the next read. An active module's flag comes on its own time: wait
// for it (flagged).
func (c *censorRun) logged(t *testing.T, match func(verdictLine) bool) bool {
	t.Helper()
	found, err := c.pollLog(match)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// flagged waits for an entry, an active module's flag, within.
func (c *censorRun) flagged(t *testing.T, within time.Duration, what string, match func(verdictLine) bool) verdictLine {
	t.Helper()
	var got verdictLine
	lab.Eventually(t, within, func() error {
		found, err := c.pollLog(func(e verdictLine) bool {
			if match(e) {
				got = e
				return true
			}
			return false
		})
		switch {
		case err != nil:
			return err
		case !found:
			return fmt.Errorf("no %s in the verdict log yet", what)
		}
		return nil
	})
	return got
}

func (c *censorRun) pollLog(match func(verdictLine) bool) (bool, error) {
	log, err := c.caughtUp()
	if err != nil {
		return false, err
	}
	return matchVerdicts(log, match)
}

// caughtUpWithin bounds caughtUp: censord decides a packet in
// microseconds and flushes every 100 ms, so only a stalled censord takes
// seconds.
const caughtUpWithin = 30 * time.Second

// caughtUp reads the queue's id_sequence, then the verdict log until its
// watermark (censor.EventWatermark) reaches it, and returns the log's
// whole lines: every packet queued before the call has its decisions in
// them. A failed read is retried until the bound. A packet netlink fails
// to deliver to censord (UserDropped) takes an id censord never sees, so
// once that count rose it fails at once with it, rather than wait out
// the bound. One dropped from a full queue (QueueDropped) takes no id
// and changes nothing here; only a failed insert into the kernel's table
// of waiting packets, rare and counted in QueueDropped too, takes one and
// waits out the bound (net/netfilter/nfnetlink_queue.c,
// __nfqnl_enqueue_packet, Linux 7.0: the full-queue check comes before
// ++id_sequence, the insert and the unicast after it). The watermark only
// grows: the kernel numbers each packet and delivers it under one lock,
// so in id order, on censord's one socket, whose callback decides them
// one at a time: no lower id comes after a higher one is handled.
func (c *censorRun) caughtUp() (string, error) {
	deadline := time.Now().Add(caughtUpWithin)
	var queued censor.QueueStats
	for {
		var err error
		if queued, err = c.stats(); err == nil {
			break
		} else if time.Now().After(deadline) {
			return "", fmt.Errorf("the queue's stats: %w", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var through uint64
	var lastErr error
	for {
		log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
		if err == nil {
			log = completeLines(log)
			if through = watermark(log); through >= queued.Sequence {
				return log, nil
			}
		}
		lastErr = err
		if now, err := c.stats(); err == nil {
			if now.UserDropped > queued.UserDropped {
				return "", fmt.Errorf("netlink failed to deliver %d packets to censord while the verdict log caught up (%d in all, queue full %d), which it can't have the decisions of",
					now.UserDropped-queued.UserDropped, now.UserDropped, now.QueueDropped)
			}
		}
		if time.Now().After(deadline) {
			now, serr := c.stats()
			return "", fmt.Errorf("the verdict log's watermark is at packet %d after %s, the kernel had queued %d (now %+v, %v; the last read: %v; censord:\n%s)",
				through, caughtUpWithin, queued.Sequence, now, serr, lastErr, c.proc.Output())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// watermark is the highest packet id the log's watermarks cover, 0 for
// none.
func watermark(log string) uint64 {
	var through uint64
	for line := range strings.Lines(log) {
		if !strings.Contains(line, `"event":"`+censor.EventWatermark+`"`) {
			continue
		}
		var e censor.LogEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.Event == censor.EventWatermark {
			through = max(through, e.Through)
		}
	}
	return through
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
		"A cell whose detail says `varies` is chance by nature, and says why: it shows what this run got, and only a `(reference)` row may vary. " +
		"A cell `not judged` crossed, but its module couldn't judge what the cell is for: the prober's upstream tell, unattributable when server-1 dialed the site outside the probes at half their rate or more.\n\n")
	b.WriteString("| transport | censor | result | detail |\n|---|---|---|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.transport, c.censor, c.result, strings.ReplaceAll(c.detail, "|", `\|`))
	}
	if err := os.WriteFile(filepath.Join(root, "lab", "RESULTS.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
