//go:build unix

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

const testVersion = "v0.0.0-test"

func TestDiagnoseServesAVersionedSnapshot(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	ctx := context.Background()
	s.node.tun = agent.InterfaceReport{Name: "utun9", Index: 21, MTU: 1328, Up: true, Running: true,
		Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/10"), netip.MustParsePrefix("fd00:1:2::2/48")}}
	before := time.Now()
	d, err := c.Diagnose(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.GetSchemaVersion() != DiagSchemaVersion || d.GetOs() != runtime.GOOS || d.GetAgentVersion() != testVersion ||
		d.GetTakenAt().AsTime().Before(before.Truncate(time.Second)) {
		t.Fatalf("header: %v", d)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(d.GetStatus(), st) {
		t.Fatalf("the snapshot's status %v, GetStatus %v", d.GetStatus(), st)
	}
	want := &localapiv1.DiagInterface{Name: "utun9", Index: 21, Mtu: 1328, Up: true, Running: true,
		Addresses: []string{"100.64.0.2/10", "fd00:1:2::2/48"}}
	if !proto.Equal(d.GetTun(), want) {
		t.Fatalf("TUN %v, want %v", d.GetTun(), want)
	}

	// As `thinkpol diag` prints it: JSON a script reads, version first.
	var out bytes.Buffer
	if err := WriteJSON(&out, d); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		SchemaVersion int `json:"schemaVersion"`
		Tun           struct {
			Name string `json:"name"`
		} `json:"tun"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil || parsed.SchemaVersion != DiagSchemaVersion || parsed.Tun.Name != "utun9" {
		t.Fatalf("JSON %+v, %v:\n%s", parsed, err, out.String())
	}

	// A part the agent couldn't read says why, and holds nothing else.
	s.node.mu.Lock()
	s.node.tun = agent.InterfaceReport{Unreadable: agent.UnreadableNoTUN, Name: "stale", MTU: 1}
	s.node.mu.Unlock()
	if d, err = c.Diagnose(ctx); err != nil || !proto.Equal(d.GetTun(), &localapiv1.DiagInterface{Unreadable: agent.UnreadableNoTUN}) {
		t.Fatalf("an unreadable TUN: %v, %v", d.GetTun(), err)
	}
}

// secretName is what a field holding a secret would be called.
var secretName = regexp.MustCompile(`(?i)key|token|secret|session|password|passphrase|credential|private|psk|cookie|seed`)

// TestTheSnapshotHasNoSecretField walks the snapshot's schema, the status
// it carries included: no field may be named for a key, a token, a
// session or a credential, so one can't be added by accident. Endpoints
// and addresses are allowed (the user reads them).
func TestTheSnapshotHasNoSecretField(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	fields := 0
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			fields++
			if secretName.MatchString(string(fd.Name())) {
				t.Errorf("%s holds %q", md.FullName(), fd.Name())
			}
			if fd.IsMap() {
				fd = fd.MapValue()
			}
			if fd.Message() != nil {
				walk(fd.Message())
			}
		}
	}
	walk((&localapiv1.Diagnostics{}).ProtoReflect().Descriptor())
	if !seen[(&localapiv1.Status{}).ProtoReflect().Descriptor().FullName()] || fields < 50 {
		t.Fatalf("walked %d fields of %d messages", fields, len(seen))
	}
}

func TestWriteJSONFileIsTheOwnersOnly(t *testing.T) {
	dir := t.TempDir()
	d := &localapiv1.Diagnostics{SchemaVersion: DiagSchemaVersion, Os: "linux"}
	path := filepath.Join(dir, "diag.json")
	check := func(t *testing.T) {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%v, %v", fi.Mode(), err)
		}
		b, _ := os.ReadFile(path)
		var got struct {
			SchemaVersion int `json:"schemaVersion"`
		}
		if err := json.Unmarshal(b, &got); err != nil || got.SchemaVersion != DiagSchemaVersion {
			t.Fatalf("%s: %v", b, err)
		}
	}

	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)

	// A file there already, open to all, is replaced by one that isn't.
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)

	// A symlink there is replaced, its target left alone: root writing
	// into a directory others can write to never follows their link.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, d); err != nil {
		t.Fatal(err)
	}
	check(t)
	if b, _ := os.ReadFile(target); string(b) != "theirs" {
		t.Fatalf("the link's target now holds %q", b)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("left behind: %v", entries)
	}
	if err := WriteJSONFile(filepath.Join(dir, "no-such-dir", "diag.json"), d); err == nil {
		t.Fatal("wrote into a directory that doesn't exist")
	}
}
