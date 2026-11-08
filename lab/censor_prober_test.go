//go:build lab

package lab_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// The fully-encrypted, prober and server-hello modules (TP-026) on the
// real thing: nginx as the camouflage site, behind the router in
// lab.Upstream, and the servers a censor should tell from it.

// camouflageName is the camouflage site's name: its certificate's, and
// the one the prober's TLS handshake asks for.
const camouflageName = "camouflage.example.net"

// startNginx runs nginx in node as an ordinary HTTPS site for name: TLS
// 1.2 and 1.3 (nginx 1.22 leaves 1.3 out unless told) on port on each of
// addrs, HTTP/2 and HTTP/1.1, a self-signed certificate, Debian's default
// page. dir keeps two in one node apart.
func startNginx(t *testing.T, node *lab.Node, dir, name string, port int, addrs []netip.Addr) {
	t.Helper()
	node.MustExec(t, "sh", "-ec", "mkdir -p "+dir+" && cd "+dir+" && "+
		"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 "+
		"-keyout key.pem -out cert.pem -subj /CN="+name+" -addext subjectAltName=DNS:"+name+" 2>/dev/null")
	var listen strings.Builder
	for _, a := range addrs {
		fmt.Fprintf(&listen, "    listen %s ssl http2;\n", netip.AddrPortFrom(a, uint16(port)))
	}
	conf := fmt.Sprintf(`worker_processes 1;
pid %[1]s/nginx.pid;
error_log stderr;
events {}
http {
  access_log off;
  client_body_temp_path %[1]s;
  proxy_temp_path %[1]s;
  fastcgi_temp_path %[1]s;
  uwsgi_temp_path %[1]s;
  scgi_temp_path %[1]s;
  server {
%[2]s    server_name %[3]s;
    ssl_certificate %[1]s/cert.pem;
    ssl_certificate_key %[1]s/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    root /var/www/html;
    index index.html index.nginx-debian.html;
  }
}
`, dir, listen.String(), name)
	node.WriteFile(t, dir+"/nginx.conf", []byte(conf))
	node.Start(t, "nginx", "-c", dir+"/nginx.conf", "-g", "daemon off;")
	waitSockets(t, node, "-lnt", port, len(addrs))
}

// startCamouflage runs the camouflage site on lab.Upstream's camouflage
// node, both families, port 443, and returns its addresses.
func startCamouflage(t *testing.T, l *lab.Lab) []netip.AddrPort {
	t.Helper()
	node := l.Node(lab.Camouflage)
	addrs := []netip.Addr{node.IPv4(lab.NetWorld), node.IPv6(lab.NetWorld)}
	startNginx(t, node, "/tmp/camouflage", camouflageName, 443, addrs)
	return []netip.AddrPort{netip.AddrPortFrom(addrs[0], 443), netip.AddrPortFrom(addrs[1], 443)}
}

// proberSettings points the prober at the camouflage site, server-1's
// connections its suspects, and fully-encrypted's tags too.
func proberSettings(t *testing.T, l *lab.Lab, camouflage []netip.AddrPort) json.RawMessage {
	t.Helper()
	server := l.Node(lab.Server1)
	b, err := json.Marshal(map[string]any{
		"reference": map[string]any{
			"name":      camouflageName,
			"addresses": []string{camouflage[0].String(), camouflage[1].String()},
		},
		"destinations": []string{server.IPv4(lab.NetServers).String(), server.IPv6(lab.NetServers).String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startEcho runs a naive echo server on server-1, both families: what a
// fully encrypted proxy looks like to a prober that doesn't know its key.
func startEcho(t *testing.T, server *lab.Node, port int) {
	t.Helper()
	for _, a := range serverAddrs(server) {
		pf := "TCP4"
		if a.Is6() {
			pf = "TCP6"
		}
		server.Start(t, "socat", fmt.Sprintf("%s-LISTEN:%d,bind=%s,fork,reuseaddr", pf, port, a), "EXEC:cat")
	}
	waitSockets(t, server, "-lnt", port, 2)
}

// randomPort is the random-tcp row's: Shadowsocks's default, though the
// modules judge any port.
const randomPort = 8388

// randomPayload is the random-tcp row's first data: random bytes but for
// a non-printable first byte, so Wu et al.'s exemptions never pass it by
// chance (six printable bytes first, once in about 400 random streams).
func randomPayload(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[0] = 0x8f
	return b
}

func setupRandom(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	startEcho(t, server, randomPort)
	dev.WriteFile(t, "/tmp/random.bin", randomPayload(t))
	return probeTarget{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

// probeRandom sends the random payload to the echo server over each
// family and checks it comes back whole.
func probeRandom(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: mustProbe(t)(untilAnswer(window(wantPass), func() (bool, error) { return randomEchoes(dev, to.v4) })),
		v6: mustProbe(t)(untilAnswer(window(wantPass), func() (bool, error) { return randomEchoes(dev, to.v6) })),
	}
}

// randomEchoes says whether the echo server sent the payload back: cmp's
// exit 0 crossed, 1 (a short or missing echo) didn't, anything else is an
// error.
func randomEchoes(dev *lab.Node, a netip.Addr) (bool, error) {
	script := fmt.Sprintf("nc -N -w 3 %s %d < /tmp/random.bin > /tmp/echo.%s; cmp -s /tmp/random.bin /tmp/echo.%s",
		a, randomPort, ncFamily(a)[1:], ncFamily(a)[1:])
	res, err := execResult(dev, pollTimeout, "sh", "-c", script)
	switch {
	case err == nil:
		return true, nil
	case res.ExitCode == 1:
		return false, nil
	}
	return false, fmt.Errorf("random echo via %s: %w\n%s", a, err, res.Stderr)
}

func sawRandom(t *testing.T, l *lab.Lab, c *censorRun) error {
	return sawFlowsTo(t, l, c, censor.ProtoTCP, randomPort, randomPort)
}

// TestFullyEncryptedRandomNotHTTPS is the ticket's first check through the
// lab censor: a Shadowsocks-like random stream is dropped by
// fully-encrypted, over both families; HTTPS to nginx crosses.
func TestFullyEncryptedRandomNotHTTPS(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server := l.Node(lab.Server1)
	to, err := setupRandom(t, l)
	if err != nil {
		t.Fatal(err)
	}
	startNginx(t, server, "/tmp/site", httpsName, 443, serverAddrs(server))
	c := startCensor(t, l, []censor.ModuleConfig{{Name: "fully-encrypted"}})

	if got := probeRandom(t, l, to, false); got.v4 || got.v6 {
		t.Errorf("the random stream crossed: %+v", got)
	}
	if got := probeHTTPS(t, l, to, true); !got.v4 || !got.v6 {
		t.Errorf("HTTPS didn't cross: %+v", got)
	}
	if _, err := blockedBy(t, l, c, "fully-encrypted"); err != nil {
		t.Error(err)
	}
	if c.logged(t, func(e verdictLine) bool {
		return e.Module == "fully-encrypted" && e.Verdict == censor.Drop && e.Key.DstPort == 443
	}) {
		t.Error("fully-encrypted dropped HTTPS")
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
}

// proberVerdict waits for the prober's flag of a flow to server-1's port
// and returns it.
func proberVerdict(t *testing.T, c *censorRun, port uint16, family func(netip.Addr) bool) verdictLine {
	t.Helper()
	var got verdictLine
	lab.Eventually(t, 60*time.Second, func() error {
		found, err := c.pollLog(func(e verdictLine) bool {
			if e.Event == censor.EventFlag && e.Module == "prober" && e.Key.DstPort == port && family(e.Key.Dst) {
				got = e
				return true
			}
			return false
		})
		switch {
		case err != nil:
			return err
		case !found:
			return fmt.Errorf("no prober flag of a flow to port %d yet", port)
		}
		return nil
	})
	return got
}

// TestProberTellsEchoFromNginx is the ticket's second and third checks
// through the lab censor, against nginx as the camouflage site: nginx on
// server-1 answers every probe as the site does and its server hello
// (JA3S, JA4S, extension order, ALPN) matches; a naive echo server is
// flagged; a relay to the site, which answers as the site does, shows the
// upstream tell, since its connection to the site crosses the censor.
func TestProberTellsEchoFromNginx(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Upstream())
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	camouflage := startCamouflage(t, l)
	startNginx(t, server, "/tmp/entry", camouflageName, 443, serverAddrs(server))
	const echoPort, relayPort = 7443, 9443
	startEcho(t, server, echoPort)
	for _, a := range serverAddrs(server) {
		ref, pf := camouflage[0], "TCP4"
		if a.Is6() {
			ref, pf = camouflage[1], "TCP6"
		}
		server.Start(t, "socat", fmt.Sprintf("%s-LISTEN:%d,bind=%s,fork,reuseaddr", pf, relayPort, a), "TCP:"+ref.String())
	}
	waitSockets(t, server, "-lnt", relayPort, 2)
	c := startCensor(t, l, []censor.ModuleConfig{{Name: "prober", Settings: proberSettings(t, l, camouflage)}})

	for _, a := range serverAddrs(server) {
		is := func(b netip.Addr) bool { return b.Is4() == a.Is4() }
		host := a.String()
		if a.Is6() {
			host = "[" + host + "]"
		}
		for _, port := range []int{443, relayPort} {
			res, err := execResult(dev, pollTimeout, "curl", "-sS", "-k", "--max-time", "5", "-o", "/dev/null",
				"--resolve", fmt.Sprintf("%s:%d:%s", camouflageName, port, host), fmt.Sprintf("https://%s:%d/", camouflageName, port))
			if err != nil {
				t.Fatalf("curl via %s:%d: %v\n%s", a, port, err, res.Stderr)
			}
		}
		dev.WriteFile(t, "/tmp/random.bin", randomPayload(t))
		_, _ = execResult(dev, pollTimeout, "sh", "-c", fmt.Sprintf("nc -N -w 2 %s %d < /tmp/random.bin > /dev/null", a, echoPort))

		nginx := proberVerdict(t, c, 443, is)
		if nginx.Verdict != censor.Accept || !strings.Contains(nginx.Reason, "answers like the reference") ||
			!strings.Contains(nginx.Reason, "JA4S t13") || !strings.Contains(nginx.Reason, `negotiated ALPN "h2"`) {
			t.Errorf("nginx via %s: %+v", a, nginx.LogEntry)
		}
		t.Logf("nginx via %s: %s", a, nginx.Reason)
		echoed := proberVerdict(t, c, echoPort, is)
		if echoed.Verdict != censor.Drop || !strings.Contains(echoed.Reason, "an echo") {
			t.Errorf("the echo server via %s: %+v", a, echoed.LogEntry)
		}
		t.Logf("echo via %s: %s", a, echoed.Reason)
		relayed := proberVerdict(t, c, relayPort, is)
		if relayed.Verdict != censor.Drop || !strings.Contains(relayed.Reason, "upstream tell") {
			t.Errorf("the relay via %s: %+v", a, relayed.LogEntry)
		}
		t.Logf("relay via %s: %s", a, relayed.Reason)
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
}

// TestServerHelloAgainstTheSite: nginx on server-1 answers curl's
// ClientHello for the camouflage site as the site does; openssl s_server
// held to TLS 1.2 doesn't, and its connection is dropped.
func TestServerHelloAgainstTheSite(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Upstream())
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	camouflage := startCamouflage(t, l)
	startNginx(t, server, "/tmp/entry", camouflageName, 443, serverAddrs(server))
	const oldPort = 8443
	server.MustExec(t, "sh", "-ec", "mkdir -p /tmp/old && cd /tmp/old && "+
		"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 "+
		"-keyout key.pem -out cert.pem -subj /CN="+camouflageName+" 2>/dev/null")
	for _, a := range serverAddrs(server) {
		server.Start(t, "openssl", "s_server", "-quiet", "-www", "-tls1_2", "-accept", netip.AddrPortFrom(a, oldPort).String(),
			"-cert", "/tmp/old/cert.pem", "-key", "/tmp/old/key.pem")
	}
	waitSockets(t, server, "-lnt", oldPort, 2)
	sites, err := json.Marshal(map[string]map[string]string{"sites": {camouflageName: camouflage[0].String()}})
	if err != nil {
		t.Fatal(err)
	}
	c := startCensor(t, l, []censor.ModuleConfig{{Name: "server-hello", Settings: sites}})

	for _, a := range serverAddrs(server) {
		host := a.String()
		if a.Is6() {
			host = "[" + host + "]"
		}
		for _, port := range []int{443, oldPort} {
			_, _ = execResult(dev, pollTimeout, "curl", "-sS", "-k", "--max-time", "3", "-o", "/dev/null",
				"--resolve", fmt.Sprintf("%s:%d:%s", camouflageName, port, host), fmt.Sprintf("https://%s:%d/", camouflageName, port))
		}
		for _, cs := range []struct {
			port    uint16
			verdict censor.Verdict
			says    string
		}{{443, censor.Accept, "server hello matches the site"}, {oldPort, censor.Drop, "server hello unlike the site"}} {
			if !c.logged(t, func(e verdictLine) bool {
				return e.Event == censor.EventFlag && e.Module == "server-hello" && e.Key.Src == a && e.Key.SrcPort == cs.port &&
					e.Verdict == cs.verdict && strings.Contains(e.Reason, cs.says)
			}) {
				t.Errorf("no %s flag %q of %s:%d in the verdict log", cs.verdict, cs.says, a, cs.port)
			}
		}
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
}

// How long settled waits: for a first tag, then for every tagged flow's
// flag (the prober takes up to about 20 s a server).
const settleQuiet, settleWithin = 5 * time.Second, 2 * time.Minute

// isServer1 says whether a is one of server-1's addresses.
func isServer1(l *lab.Lab) func(netip.Addr) bool {
	server := l.Node(lab.Server1)
	return func(a netip.Addr) bool { return a == server.IPv4(lab.NetServers) || a == server.IPv6(lab.NetServers) }
}

// settled waits until every flow of server-1 a passive module tagged has
// an active module's flag: the active modules have judged what they were
// shown. With no tag within settleQuiet, nothing was suspect.
func (c *censorRun) settled(t *testing.T, l *lab.Lab) error {
	t.Helper()
	isServer := isServer1(l)
	start := time.Now()
	for {
		log, err := execRead(c.router, pollTimeout, "cat", censorLogPath)
		if err == nil {
			tagged, flagged := map[string]bool{}, map[string]bool{}
			if _, err := matchVerdicts(completeLines(log), func(e verdictLine) bool {
				if isServer(e.Key.Src) || isServer(e.Key.Dst) {
					tagged[e.Flow] = tagged[e.Flow] || e.Event == censor.EventTag
					flagged[e.Flow] = flagged[e.Flow] || e.Event == censor.EventFlag
				}
				return false
			}); err != nil {
				return err
			}
			waiting, tags := 0, 0
			for f, tag := range tagged {
				if tag {
					tags++
					if !flagged[f] {
						waiting++
					}
				}
			}
			switch {
			case tags > 0 && waiting == 0, tags == 0 && time.Since(start) > settleQuiet:
				t.Logf("settled after %s: %d tagged flows of server-1, all flagged", time.Since(start).Round(time.Second), tags)
				return nil
			case time.Since(start) > settleWithin:
				return fmt.Errorf("%d of %d flows of server-1 a module tagged have no flag after %s", waiting, tags, settleWithin)
			}
		} else if time.Since(start) > settleWithin {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// judged is module's first flag of a flow of server-1, its reason, "" for
// none.
func (c *censorRun) judged(t *testing.T, l *lab.Lab, module string) string {
	t.Helper()
	isServer := isServer1(l)
	var why string
	c.logged(t, func(e verdictLine) bool {
		if e.Event == censor.EventFlag && e.Module == module && (isServer(e.Key.Src) || isServer(e.Key.Dst)) {
			why = fmt.Sprintf("%s, %s", e.Verdict, e.Reason)
			return true
		}
		return false
	})
	return why
}
