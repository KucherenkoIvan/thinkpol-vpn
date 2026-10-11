//go:build lab

package lab_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestIngressOffAdmitsOnlyServers turns server-2's ingress off under a
// running space (lab/maps/ingress.yaml). device-b keeps its old map, so it
// still has server-2's address and a credential that the server's new
// section lists, and is refused all the same; device-a still reaches
// server-2 through server-1, which server-2 admits as a server. A spec
// asking a device to dial server-2 with ingress off doesn't build at all.
func TestIngressOffAdmitsOnlyServers(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	s1, s2, devA, devB := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA), l.Node(lab.DeviceB)
	space := &m0Space{builder: l.Node(lab.Internet), spec: "/src/lab/maps/ingress.yaml", env: []string{
		"SERVER_1_IPV4=" + s1.IPv4(lab.NetServers).String(),
		"SERVER_2_IPV4=" + s2.IPv4(lab.NetServers).String(),
		"SERVER_2_INGRESS=false",
	}}
	space.builder.MustExec(t, "sh", "-ec", `mkdir -p /tmp/m0 && cd /tmp/m0
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 server-2 device-a device-b >/dev/null`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refused, err := space.builder.Exec(ctx, append(append([]string{"env"}, space.env...),
		"sh", "-ec", "cd /tmp/m0 && thinkpol dev map build -keys keys -out map.bin "+space.spec)...)
	if err == nil || !strings.Contains(refused.Stderr, "server-2 has ingress off, so device-b can't connect to it") {
		t.Fatalf("a spec giving device-b server-2's address with ingress off: %v\n%s%s", err, refused.Stdout, refused.Stderr)
	}

	space.env[2] = "SERVER_2_INGRESS=true"
	v1, version1 := space.build(t)
	nodes := map[string]*lab.Node{"server-1": s1, "server-2": s2, "device-a": devA, "device-b": devB}
	for name, n := range nodes {
		space.install(t, n, name, v1)
	}
	up := map[string]*lab.Process{
		// server-1 runs its data plane in-process on its own sockets: a
		// worker's dials out of its namespace (to server-2) come with TP-014.
		"server-1": s1.Start(t, "thinkpol", "up", "-map-poll", "1s", "-mode", "device"),
		"server-2": s2.Start(t, "thinkpol", "up", "-map-poll", "1s", "-log-level", "debug"),
		"device-a": devA.Start(t, "thinkpol", "up", "-map-poll", "1s"),
		"device-b": devB.Start(t, "thinkpol", "up", "-map-poll", "1s"),
	}
	waitLog(t, up["server-2"], `msg="map applied" version=`+version1+` .*ingress=true egress=false`)

	server2 := netip.AddrFrom4([4]byte{100, 64, 0, 2}) // overlay addresses go in spec order
	ping(t, devB, server2)                             // directly: device-b's credential works
	ping(t, devA, server2)                             // through server-1

	v2, version2 := ingressOff(t, space, v1, "server-2", "device-b")
	for _, name := range []string{"server-1", "server-2", "device-a"} {
		putMap(t, nodes[name], v2)
	}
	waitLog(t, up["server-2"], `msg="map applied" version=`+version2+` .*ingress=false egress=false`)
	waitLog(t, up["server-2"], `worker space=\S+ .*msg=skipped entry="inbound link [0-9a-f]+: ingress off`)
	waitLog(t, up["server-1"], applied(version2))
	waitLog(t, up["device-a"], applied(version2))

	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := devB.Exec(ctx, "ping", "-c", "1", "-W", "1", server2.String())
		cancel()
		if err == nil {
			t.Fatalf("ping %d: device-b reached server-2 with its ingress off", i)
		}
	}
	ping(t, devA, server2) // server-1 still relays to server-2

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
}

// ingressOff derives the next map from envelope with server's ingress off
// and device's section left out: the device keeps the map it has, with the
// server's address and its credential, which the server's own section
// still lists. Every other section is reopened with its node's key from
// the builder, so only the setting and the version change.
func ingressOff(t *testing.T, s *m0Space, envelope []byte, server, device string) ([]byte, string) {
	t.Helper()
	field := func(file, name string) string {
		m := regexp.MustCompile(name + `: "([0-9a-f]+)"`).FindSubmatch(s.file(t, file))
		if m == nil {
			t.Fatalf("no %s in %s", name, file)
		}
		return string(m[1])
	}
	seed, err := hex.DecodeString(field("keys/space.key", "signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	signing := ed25519.NewKeyFromSeed(seed)
	m, err := netmap.Verify(envelope, netmap.Trust{SigningKey: signing.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	h := m.Header()
	c := netmap.Contents{SpaceID: h.SpaceID, KeyEpoch: h.KeyEpoch, Version: h.Version + 1, RecoveryKey: h.RecoveryKey, Blobs: h.Blobs}
	for _, name := range []string{"server-1", "server-2", "device-a", "device-b"} {
		if name == device {
			continue
		}
		key, err := netmap.ParseNodePrivateKey(field("keys/"+name+".key", "map-key"))
		if err != nil {
			t.Fatal(err)
		}
		sec, err := m.Open(key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == server {
			sec.Node.AllowIngress = false
		}
		c.Recipients = append(c.Recipients, netmap.Recipient{Key: key.Public(), Section: sec})
	}
	next, err := netmap.Build(signing, c)
	if err != nil {
		t.Fatal(err)
	}
	return next, strconv.FormatUint(c.Version, 10)
}
