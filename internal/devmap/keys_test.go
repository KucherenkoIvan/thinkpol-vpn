package devmap

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeyFilesRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	space, err := NewSpaceKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSpaceKeys(dir, space); err != nil {
		t.Fatal(err)
	}
	node, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNodeKey(dir, "device-a", node); err != nil {
		t.Fatal(err)
	}

	sk, err := ReadSpaceKeys(filepath.Join(dir, SpaceKeyFile))
	if err != nil || sk.ID != space.ID || !sk.Signing.Equal(space.Signing) {
		t.Fatalf("space key %v, %v", sk.ID, err)
	}
	trust, err := ReadTrust(filepath.Join(dir, TrustFile))
	want := space.Trust()
	if err != nil || trust.SpaceID != want.SpaceID || !bytes.Equal(trust.SigningKey, want.SigningKey) || !bytes.Equal(trust.RecoveryKey, want.RecoveryKey) {
		t.Fatalf("trust %+v, %v", trust, err)
	}
	nk, err := ReadNodeKey(filepath.Join(dir, "device-a.key"))
	if err != nil || nk != node {
		t.Fatalf("node key: %v", err)
	}
	pub, err := ReadNodePublic(filepath.Join(dir, "device-a.pub"))
	if err != nil || pub != node.Public() {
		t.Fatalf("node public: %v", err)
	}
	names, err := ReadNames(dir, space.ID)
	if err != nil || len(names) != 1 || names[NodeID(space.ID, pub.Map)] != "device-a" {
		t.Fatalf("names %v, %v", names, err)
	}

	// The recovery key is in its own file, readable as a key file.
	rec := readFile(t, filepath.Join(dir, RecoveryKeyFile))
	if !bytes.Contains(rec, []byte(space.ID.String())) || !strings.HasPrefix(string(rec), "# thinkpol development keys.") {
		t.Fatalf("recovery.key:\n%s", rec)
	}
}

func TestPrivateKeyFilesAre0600AndNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	space, _ := NewSpaceKeys(nil)
	node, _ := NewNodeKey(nil)
	if err := WriteSpaceKeys(dir, space); err != nil {
		t.Fatal(err)
	}
	if err := WriteNodeKey(dir, "server-1", node); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for file, want := range map[string]os.FileMode{
			SpaceKeyFile: 0o600, RecoveryKeyFile: 0o600, TrustFile: 0o644, "server-1.key": 0o600, "server-1.pub": 0o644,
		} {
			fi, err := os.Stat(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != want {
				t.Errorf("%s: mode %v, want %v", file, fi.Mode().Perm(), want)
			}
		}
	}

	before := readFile(t, filepath.Join(dir, "server-1.key"))
	other, _ := NewNodeKey(nil)
	if err := WriteNodeKey(dir, "server-1", other); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Fatalf("second write: %v", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, "server-1.key")), before) {
		t.Fatal("key file replaced")
	}
	// A space whose files partly exist is refused before anything is written.
	if err := os.Remove(filepath.Join(dir, SpaceKeyFile)); err != nil {
		t.Fatal(err)
	}
	other2, _ := NewSpaceKeys(nil)
	if err := WriteSpaceKeys(dir, other2); err == nil {
		t.Fatal("space keys written over an existing recovery key")
	}
	if _, err := os.Stat(filepath.Join(dir, SpaceKeyFile)); !os.IsNotExist(err) {
		t.Fatal("a space key was written next to another space's recovery key")
	}
	if err := WriteNodeKey(dir, "../escape", other); err == nil {
		t.Fatal("node name with a path accepted")
	}
}

func TestWireGuardKeyIsClampedCurve25519(t *testing.T) {
	k, err := NewNodeKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.WireGuard[0]&7 != 0 || k.WireGuard[31]&0x80 != 0 || k.WireGuard[31]&0x40 == 0 {
		t.Fatal("WireGuard private key not clamped")
	}
	want, _ := curve25519.X25519(k.WireGuard[:], curve25519.Basepoint)
	if pub := k.Public().WireGuard; !bytes.Equal(pub[:], want) {
		t.Fatal("WireGuard public key is not X25519 of the private key")
	}
	if s := k.WireGuard.String(); strings.Contains(s, "%") || !strings.Contains(s, "redacted") {
		t.Fatalf("String() = %q", s)
	}
}

func TestLoadKeysChecksTheSpaceFilesMatch(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewSpaceKeys(nil)
	b, _ := NewSpaceKeys(nil)
	if err := WriteSpaceKeys(dir, a); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := WriteSpaceKeys(other, b); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(other, TrustFile), filepath.Join(dir, TrustFile)); err != nil {
		t.Fatal(err)
	}
	f := labFixture(t)
	if _, err := LoadKeys(dir, f.spec); err == nil || !strings.Contains(err.Error(), "are not of the same space") {
		t.Fatalf("err %v", err)
	}
}

func TestKeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := ReadNodeKey(write("a.key", "map-key: 00\nwireguard-key: 00\n")); err == nil || !strings.Contains(err.Error(), "map-key must be 32 hex bytes") {
		t.Errorf("short key: %v", err)
	}
	if _, err := ReadNodeKey(write("b.key", "map-key: 00\nextra: 1\n")); err == nil || !strings.Contains(err.Error(), `b.key:2:1: unknown field "extra"`) {
		t.Errorf("unknown field: %v", err)
	}
	// Hex that YAML would take for numbers is read as written.
	digits, float := strings.Repeat("12", 32), "1e"+strings.Repeat("0", 62)
	k, err := ReadNodeKey(write("d.key", "map-key: "+digits+"\nwireguard-key: "+float+"\n"))
	if err != nil || hex.EncodeToString(k.Map[:]) != digits || hex.EncodeToString(k.WireGuard[:]) != float {
		t.Errorf("numeric-looking hex: %v", err)
	}
	low := strings.Repeat("00", 32) // a low-order point
	if _, err := ReadNodePublic(write("c.pub", "map-key: "+low+"\nwireguard-key: "+low+"\n")); err == nil || !strings.Contains(err.Error(), "low-order") {
		t.Errorf("low-order public key: %v", err)
	}
}
