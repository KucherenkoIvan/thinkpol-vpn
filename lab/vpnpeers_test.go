//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// The matrix's control and reference rows beyond plain TCP: HTTPS to a
// site no list names, and real WireGuard and OpenVPN, what the
// fingerprint modules must block. Each runs once over each underlay
// family (one tunnel per family, so a family a censor misses shows), and
// each starts its handshake in the probe, after the censor is up, so the
// censor sees the connection from its first packet.

// httpsName is the name the https row's ClientHello asks for.
const httpsName = "site.example.net"

func setupHTTPS(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server := l.Node(lab.Server1)
	server.MustExec(t, "sh", "-ec", "mkdir -p /tmp/https && cd /tmp/https && "+
		"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 "+
		"-keyout key.pem -out cert.pem -subj /CN="+httpsName+" -addext subjectAltName=DNS:"+httpsName+" 2>/dev/null")
	for _, a := range serverAddrs(server) {
		server.Start(t, "openssl", "s_server", "-quiet", "-www", "-accept", netip.AddrPortFrom(a, 443).String(),
			"-cert", "/tmp/https/cert.pem", "-key", "/tmp/https/key.pem")
	}
	waitSockets(t, server, "-lnt", 443, 2)
	return probeTarget{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

// probeHTTPS fetches a page from server-1 over each family, by name.
func probeHTTPS(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	get := func(a netip.Addr) (bool, error) {
		return untilAnswer(window(wantPass), func() (bool, error) { return httpsFetches(dev, a) })
	}
	return crossed{v4: mustProbe(t)(get(to.v4)), v6: mustProbe(t)(get(to.v6))}
}

// httpsFetches says whether one HTTPS request to httpsName at a got a 200.
// "Doesn't cross" is curl failing to connect, timing out, or having the
// connection reset or closed under it, its TLS handshake included; any
// other failure is an error.
func httpsFetches(dev *lab.Node, a netip.Addr) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host := a.String()
	if a.Is6() {
		host = "[" + host + "]"
	}
	res, err := dev.Exec(ctx, "curl", "-sS", "-k", "--max-time", "3", "-o", "/dev/null", "-w", "%{http_code}",
		"--resolve", httpsName+":443:"+host, "https://"+httpsName+"/")
	switch {
	case err == nil && strings.TrimSpace(res.Stdout) == "200":
		return true, nil
	case err == nil:
		return false, fmt.Errorf("https to %s: status %q", a, res.Stdout)
	}
	switch {
	case res.ExitCode == 7, res.ExitCode == 28, res.ExitCode == 52, res.ExitCode == 56: // connect failed, timed out, empty reply, reset
		return false, nil
	case res.ExitCode == 35 && strings.Contains(res.Stderr, "reset by peer"):
		// A TLS handshake failure is a block only when the connection was
		// reset under it; a handshake that failed otherwise is broken.
		return false, nil
	}
	return false, fmt.Errorf("https to %s: %w\n%s", a, err, res.Stderr)
}

func sawHTTPS(t *testing.T, l *lab.Lab, c *censorRun) error {
	return sawFlowsTo(t, l, c, censor.ProtoTCP, 443, 443)
}

// sawFlowsTo checks the verdict log has a flow from device-a to server-1
// over each family, IPv4 to port4 and IPv6 to port6.
func sawFlowsTo(t *testing.T, l *lab.Lab, c *censorRun, proto censor.Proto, port4, port6 uint16) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		dst, port := serverAddrFor(server, src), port4
		if src.Is6() {
			port = port6
		}
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == proto && e.Key.Src == src && e.Key.Dst == dst && e.Key.DstPort == port
		}) {
			return fmt.Errorf("no %s flow %s -> %s in the verdict log", proto, src, netip.AddrPortFrom(dst, port))
		}
	}
	return nil
}

// waitSockets waits for n sockets listening on port in node; kind is
// ss's -lnt or -lnu.
func waitSockets(t *testing.T, node *lab.Node, kind string, port, n int) {
	t.Helper()
	lab.Eventually(t, 30*time.Second, func() error {
		out, err := execRead(node, pollTimeout, "ss", "-H", kind, fmt.Sprintf("sport = :%d", port))
		if err != nil {
			return err
		}
		if got := strings.TrimSpace(out); got == "" || len(strings.Split(got, "\n")) < n {
			return fmt.Errorf("sockets on %d: %q", port, out)
		}
		return nil
	})
}

// The reference tunnels' ports and overlay addresses, by underlay family:
// server-1 is .1 and device-a .2 of each /24. The ports are not WireGuard's
// and OpenVPN's defaults: the fingerprints must match on any port.
const (
	wgPort4, wgPort6     = 443, 4443
	ovpnPort4, ovpnPort6 = 8443, 9443
)

var (
	wgOverlay   = map[bool]string{false: "10.99.4", true: "10.99.6"}
	ovpnOverlay = map[bool]string{false: "10.98.4", true: "10.98.6"}
)

func overlayTarget(prefix map[bool]string) probeTarget {
	return probeTarget{netip.MustParseAddr(prefix[false] + ".1"), netip.MustParseAddr(prefix[true] + ".1")}
}

// setupWireGuard configures kernel WireGuard between device-a and
// server-1, one interface per underlay family. Nothing is sent until the
// probe's first ping: WireGuard handshakes on demand.
func setupWireGuard(t *testing.T, l *lab.Lab) (probeTarget, error) {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	keys := map[*lab.Node]string{}
	for _, n := range []*lab.Node{dev, server} {
		n.MustExec(t, "sh", "-ec", "umask 077 && wg genkey > /tmp/wg.key")
		keys[n] = strings.TrimSpace(n.MustExec(t, "sh", "-ec", "wg pubkey < /tmp/wg.key"))
	}
	for _, v6 := range []bool{false, true} {
		ifname, port := "wg4", wgPort4
		if v6 {
			ifname, port = "wg6", wgPort6
		}
		endpoint := netip.AddrPortFrom(serverAddrFor(server, familyAddr(v6)), uint16(port))
		for _, side := range []struct {
			n, peer    *lab.Node
			own, other string
			endpoint   []string
		}{
			{server, dev, ".1", ".2", nil},
			{dev, server, ".2", ".1", []string{"endpoint", endpoint.String()}},
		} {
			side.n.MustExec(t, "ip", "link", "add", ifname, "type", "wireguard")
			args := []string{"wg", "set", ifname, "private-key", "/tmp/wg.key", "listen-port", fmt.Sprint(port),
				"peer", keys[side.peer], "allowed-ips", wgOverlay[v6] + side.other + "/32"}
			side.n.MustExec(t, append(args, side.endpoint...)...)
			side.n.MustExec(t, "ip", "addr", "add", wgOverlay[v6]+side.own+"/24", "dev", ifname)
			side.n.MustExec(t, "ip", "link", "set", ifname, "up")
		}
	}
	return overlayTarget(wgOverlay), nil
}

func sawWireGuard(t *testing.T, l *lab.Lab, c *censorRun) error {
	return sawFlowsTo(t, l, c, censor.ProtoUDP, wgPort4, wgPort6)
}

// openVPN is the reference OpenVPN row over one transport protocol, udp
// or tcp: TLS mode, point to point, certificates of a lab CA.
type openVPN struct{ proto string }

func (o openVPN) ipProto() censor.Proto {
	if o.proto == "tcp" {
		return censor.ProtoTCP
	}
	return censor.ProtoUDP
}

// protoFor is OpenVPN's --proto for a side and family: udp4, tcp6-server.
func (o openVPN) protoFor(server, v6 bool) string {
	p := o.proto + "4"
	if v6 {
		p = o.proto + "6"
	}
	if o.proto == "tcp" {
		if server {
			return p + "-server"
		}
		return p + "-client"
	}
	return p
}

// setup makes the lab CA's certificates and starts server-1's OpenVPN,
// one per family.
func (o openVPN) setup(t *testing.T, l *lab.Lab) (probeTarget, error) {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	const ec = "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2"
	server.MustExec(t, "sh", "-ec", "mkdir -p /tmp/ovpn && cd /tmp/ovpn && "+
		"openssl req -x509 "+ec+" -keyout ca.key -out ca.crt -subj /CN=lab-ca 2>/dev/null && "+
		"for n in server client; do "+
		"openssl req "+ec+" -keyout $n.key -out $n.csr -subj /CN=$n 2>/dev/null && "+
		"openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -out $n.crt 2>/dev/null; done")
	for _, f := range []string{"ca.crt", "client.crt", "client.key"} {
		dev.WriteFile(t, "/tmp/ovpn/"+f, []byte(server.MustExec(t, "cat", "/tmp/ovpn/"+f)))
	}
	t.Logf("openvpn: %s", strings.SplitN(server.MustExec(t, "sh", "-c", "openvpn --version | head -1"), "\n", 2)[0])
	for _, v6 := range []bool{false, true} {
		ifname, port := "ovpn4", ovpnPort4
		if v6 {
			ifname, port = "ovpn6", ovpnPort6
		}
		server.Start(t, "openvpn", "--dev", ifname, "--dev-type", "tun", "--proto", o.protoFor(true, v6),
			"--local", serverAddrFor(server, familyAddr(v6)).String(), "--lport", fmt.Sprint(port),
			"--tls-server", "--dh", "none", "--ca", "/tmp/ovpn/ca.crt", "--cert", "/tmp/ovpn/server.crt", "--key", "/tmp/ovpn/server.key",
			"--ifconfig", ovpnOverlay[v6]+".1", ovpnOverlay[v6]+".2", "--verb", "3")
	}
	kind := "-lnu"
	if o.proto == "tcp" {
		kind = "-lnt"
	}
	for _, port := range []int{ovpnPort4, ovpnPort6} {
		waitSockets(t, server, kind, port, 1)
	}
	return overlayTarget(ovpnOverlay), nil
}

// familyAddr is an address of the family, for serverAddrFor.
func familyAddr(v6 bool) netip.Addr {
	if v6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

// probe starts device-a's OpenVPN clients, the handshake crossing the
// censor, and pings server-1 through each. Until a client's tun is up its
// overlay has no route: ping sends nothing and fails with "Network is
// unreachable", which counts as no reply (pingNoReplyOrRoute). A blocked
// cell still needs the verdict log to blame the handshake (blockedBy), so
// a tunnel that never came up for another reason isn't scored blocked.
func (o openVPN) probe(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	for _, v6 := range []bool{false, true} {
		ifname, port := "ovpn4", ovpnPort4
		if v6 {
			ifname, port = "ovpn6", ovpnPort6
		}
		dev.Start(t, "openvpn", "--dev", ifname, "--dev-type", "tun", "--proto", o.protoFor(false, v6),
			"--remote", serverAddrFor(server, familyAddr(v6)).String(), "--rport", fmt.Sprint(port), "--nobind",
			"--tls-client", "--ca", "/tmp/ovpn/ca.crt", "--cert", "/tmp/ovpn/client.crt", "--key", "/tmp/ovpn/client.key",
			"--ifconfig", ovpnOverlay[v6]+".2", ovpnOverlay[v6]+".1", "--connect-retry", "1", "1", "--verb", "3")
	}
	return crossed{
		v4: mustProbe(t)(pingCrosses(dev, to.v4, window(wantPass), pingNoReplyOrRoute)),
		v6: mustProbe(t)(pingCrosses(dev, to.v6, window(wantPass), pingNoReplyOrRoute)),
	}
}

func (o openVPN) sawFlows(t *testing.T, l *lab.Lab, c *censorRun) error {
	return sawFlowsTo(t, l, c, o.ipProto(), ovpnPort4, ovpnPort6)
}
