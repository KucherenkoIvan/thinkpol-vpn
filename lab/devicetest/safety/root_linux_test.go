package safety

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/pcap"
)

// The core as root, in a lab node: the launch script's root copy, and a
// capture (a root process) applied and undone through the journal.

func needsLabRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the lab runs tests as root")
	}
}

func rootCopies(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(rootCopyBase + "/tpdt.*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTheRootCopyIsRootsAndChecked(t *testing.T) {
	needsLabRoot(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	before := len(rootCopies(t))
	cmd, err := RootCommand(self, []string{"rootcheck"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "root copy ok") {
		t.Fatalf("the root copy: %s %v", out, err)
	}
	if n := len(rootCopies(t)); n != before {
		t.Errorf("root copies left: %d, before %d", n, before)
	}

	// A binary that isn't the one hashed is refused, and nothing is left.
	sum, err := fileSHA256(self)
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("0", len(sum))
	bad := exec.Command("/bin/sh", "-c", launchScript, "devicetest-launch", self, wrong, rootCopyBase, hasher, "rootcheck")
	bad.Env = append(os.Environ(), childEnv+"=1")
	out, err = bad.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "hash") || strings.Contains(string(out), "root copy ok") {
		t.Fatalf("a wrong hash: %s %v", out, err)
	}
	if n := len(rootCopies(t)); n != before {
		t.Errorf("a refused copy was left: %d, before %d", n, before)
	}

	// A helper refused before its run starts removes its root copy.
	refused, err := RootCommand(self, []string{"helper", "-run", "x"})
	if err != nil {
		t.Fatal(err)
	}
	refused.Env = append(os.Environ(), childEnv+"=1", nonRootEnv+"=")
	if out, err := refused.CombinedOutput(); err == nil {
		t.Fatalf("a helper without its flags ran: %s", out)
	}
	if n := len(rootCopies(t)); n != before {
		t.Errorf("a refused helper left its root copy: %d, before %d", n, before)
	}

	// The checks themselves: a directory that isn't a root copy's.
	if err := checkRootCopy(t.TempDir()); err == nil {
		t.Error("a test directory passed as a root copy")
	}
}

// nodeInterface is the node's lab interface and its IPv4 network.
func nodeInterface(t *testing.T) (string, *net.IPNet) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				return ifc.Name, n
			}
		}
	}
	t.Fatal("no interface with IPv4")
	return "", nil
}

// sendMarker sends one marker datagram to the network's broadcast address,
// port 9 (discard), from port sport.
func sendMarker(t *testing.T, n *net.IPNet, sport int, payload string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: sport, Addr: [4]byte(n.IP.To4())}); err != nil {
		t.Fatal(err)
	}
	bcast := make(net.IP, 4)
	for i := range bcast {
		bcast[i] = n.IP.To4()[i] | ^n.Mask[i]
	}
	if err := syscall.Sendto(fd, []byte(payload), 0, &syscall.SockaddrInet4{Port: 9, Addr: [4]byte(bcast)}); err != nil {
		t.Fatal(err)
	}
}

func TestACaptureIsUndoneThroughTheJournal(t *testing.T) {
	needsLabRoot(t)
	iface, n := nodeInterface(t)
	h, _ := testHost(t, "boot-a")
	evidenceDir := tempDir(t)
	ev, err := openEvidence(evidenceDir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.evidence, h.captures = ev, &captures{live: map[string]*liveCapture{}, ev: ev}
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	params, _ := json.Marshal(captureAction{Iface: iface, Filter: "not (udp src port 40002) and udp dst port 9"})
	if _, err := e.do(t.Context(), Spec{Kind: KindCapture, Params: params}); err != nil {
		t.Fatal(err)
	}
	var applied captureAction
	if err := json.Unmarshal(j.entries()[0].Params, &applied); err != nil || !running(applied.PID, applied.Start) {
		t.Fatalf("the journal doesn't name the running tcpdump: %+v %v", applied, err)
	}
	c, err := h.captures.get(iface)
	if err != nil {
		t.Fatal(err)
	}
	sendMarker(t, n, 40002, MarkerPrefix+"r filtered")
	sendMarker(t, n, 40001, MarkerPrefix+"r seen")
	if !c.seen(t.Context(), "seen", 5*time.Second) {
		t.Fatal("the marker wasn't seen")
	}
	if c.seen(t.Context(), "filtered", 200*time.Millisecond) {
		t.Error("the filtered marker was seen: the filter isn't applied")
	}
	// A plan can't end the run's capture; the restore does.
	if err := e.undoLast(t.Context()); err == nil {
		t.Fatal("undoLast ended the capture")
	}
	if res := e.restore(t.Context(), "test"); res.Verdict != Clean {
		t.Fatalf("restore: %+v", res)
	}
	if running(applied.PID, applied.Start) {
		t.Error("tcpdump outlived its undo")
	}
	assertPcapHas(t, filepath.Join(evidenceDir, "captures", iface+".pcap"), "seen", "filtered")
}

// assertPcapHas reads a pcap file back: the marker with nonce want is in
// it, the one with nonce not isn't.
func assertPcapHas(t *testing.T, path, want, not string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcap.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		found = found || bytes.HasSuffix(p.Payload, []byte(" "+want))
		if bytes.HasSuffix(p.Payload, []byte(" "+not)) {
			t.Errorf("%s holds %q", path, not)
		}
	}
	if !found {
		t.Errorf("%s doesn't hold %q", path, want)
	}
}
