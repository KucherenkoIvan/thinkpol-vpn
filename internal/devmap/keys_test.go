package devmap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func TestKeyFilesRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	offline := filepath.Join(t.TempDir(), "offline")
	space, err := GenerateSpace(dir, offline)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := GenerateNodes(dir, []string{"device-a", "server-1"})
	if err != nil {
		t.Fatal(err)
	}

	sk, err := ReadSpaceKeys(filepath.Join(dir, SpaceKeyFile))
	if err != nil || sk.ID != space.ID || sk.IPv6Network != space.IPv6Network || !sk.Signing.Equal(space.Signing) {
		t.Fatalf("space key %v, %v", sk, err)
	}
	trust, err := ReadTrust(filepath.Join(dir, TrustFile))
	want := space.Trust()
	if err != nil || trust.SpaceID != want.SpaceID || !bytes.Equal(trust.SigningKey, want.SigningKey) || !bytes.Equal(trust.RecoveryKey, want.RecoveryKey) {
		t.Fatalf("trust %+v, %v", trust, err)
	}
	for i, name := range []string{"device-a", "server-1"} {
		k, err := ReadNodeKey(filepath.Join(dir, name+".key"))
		if err != nil || k != nodes[i] {
			t.Fatalf("%s key: %v", name, err)
		}
		pub, err := ReadNodePublic(filepath.Join(dir, name+".pub"))
		if err != nil || pub != nodes[i].Public() {
			t.Fatalf("%s public: %v", name, err)
		}
	}
	names, err := ReadNames(dir)
	if err != nil || len(names) != 2 || names[nodes[0].ID] != "device-a" || names[nodes[1].ID] != "server-1" {
		t.Fatalf("names %v, %v", names, err)
	}

	// The recovery key went where it was told, and only there.
	if _, err := os.Stat(filepath.Join(dir, RecoveryKeyFile)); !os.IsNotExist(err) {
		t.Fatal("recovery.key written next to the signing key")
	}
	rec := readFile(t, filepath.Join(offline, RecoveryKeyFile))
	if !bytes.Contains(rec, []byte(hex.EncodeToString(space.Recovery.Seed()))) || !strings.HasPrefix(string(rec), "# thinkpol development keys.") {
		t.Fatalf("recovery.key:\n%s", rec)
	}
}

// Every space is random: its id, its /48 and its keys; every node id too.
func TestGeneratedValuesAreRandom(t *testing.T) {
	a, _ := NewSpaceKeys(nil)
	b, _ := NewSpaceKeys(nil)
	if a.ID == b.ID || a.IPv6Network == b.IPv6Network || a.Signing.Equal(b.Signing) {
		t.Fatal("two spaces share values")
	}
	if !ula.Contains(a.IPv6Network.Addr()) || a.IPv6Network.Bits() != 48 || a.IPv6Network != a.IPv6Network.Masked() {
		t.Fatalf("IPv6 network %v", a.IPv6Network)
	}
	m, _ := NewNodeKeys(nil)
	n, _ := NewNodeKeys(nil)
	if m.ID == n.ID || m.ID.IsZero() || m.Map == n.Map || m.WireGuard == n.WireGuard {
		t.Fatal("two nodes share values")
	}
	if m.WireGuard[0]&7 != 0 || m.WireGuard[31]&0x80 != 0 || m.WireGuard[31]&0x40 == 0 {
		t.Fatal("WireGuard private key not clamped")
	}
}

// Files get exactly 0600 or 0644 whatever the umask.
func TestKeyFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix modes")
	}
	for _, umask := range []int{0o077, 0o000, 0o022} {
		t.Run(fmt.Sprintf("umask %04o", umask), func(t *testing.T) {
			restore := setUmask(umask)
			defer restore()
			dir := t.TempDir()
			if _, err := GenerateSpace(dir, dir); err != nil {
				t.Fatal(err)
			}
			if _, err := GenerateNodes(dir, []string{"server-1"}); err != nil {
				t.Fatal(err)
			}
			if err := WriteMap(filepath.Join(dir, "map.bin"), []byte("x")); err != nil {
				t.Fatal(err)
			}
			for file, want := range map[string]os.FileMode{
				SpaceKeyFile: 0o600, RecoveryKeyFile: 0o600, TrustFile: 0o644, "server-1.key": 0o600, "server-1.pub": 0o644, "map.bin": 0o644,
			} {
				fi, err := os.Stat(filepath.Join(dir, file))
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != want {
					t.Errorf("%s: mode %v, want %v", file, fi.Mode().Perm(), want)
				}
			}
		})
	}
}

func TestPrivateKeyFilesOthersCanReadAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix modes")
	}
	dir := t.TempDir()
	if _, err := GenerateSpace(dir, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateNodes(dir, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		for _, file := range []string{"a.key", SpaceKeyFile} {
			path := filepath.Join(dir, file)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			var err error
			if file == SpaceKeyFile {
				_, err = ReadSpaceKeys(path)
			} else {
				_, err = ReadNodeKey(path)
			}
			if err == nil || !strings.Contains(err.Error(), "lets others read a private key") {
				t.Errorf("%s at %v: %v", file, mode, err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := ReadNodeKey(filepath.Join(dir, "a.key")); err != nil {
		t.Fatal(err)
	}
}

// A keygen run writes all its files or none, and never replaces one.
func TestKeygenIsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateNodes(dir, []string{"b"}); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, filepath.Join(dir, "b.key"))
	for _, names := range [][]string{
		{"a", "b", "c"},   // b exists
		{"a", "c", "a"},   // a twice
		{"a", "../c"},     // a path
		{"a", "recovery"}, // a space file
		{"a", "C"},        // not a name
	} {
		if _, err := GenerateNodes(dir, names); err == nil {
			t.Errorf("%v accepted", names)
		}
		if _, err := os.Stat(filepath.Join(dir, "a.key")); !os.IsNotExist(err) {
			t.Fatalf("%v: a.key written", names)
		}
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, "b.key")), before) {
		t.Fatal("b.key replaced")
	}

	// A space whose recovery key exists is refused before anything is
	// written; one that can't write its last file leaves nothing behind.
	if err := os.WriteFile(filepath.Join(dir, RecoveryKeyFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSpace(dir, dir); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Fatalf("over a recovery key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, SpaceKeyFile)); !os.IsNotExist(err) {
		t.Fatal("space.key written next to another space's recovery key")
	}
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "keys")
	if _, err := GenerateSpace(other, notADir); err == nil {
		t.Fatal("recovery key written into a file")
	}
	if entries, _ := os.ReadDir(other); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestKeysPrintRedacted(t *testing.T) {
	space, _ := NewSpaceKeys(nil)
	keys := Keys{Space: space.ID, Signing: space.Signing}
	node, _ := NewNodeKeys(nil)
	secrets := []string{hex.EncodeToString(space.Signing.Seed()), hex.EncodeToString(space.Recovery.Seed()), hex.EncodeToString(node.Map[:]), hex.EncodeToString(node.WireGuard[:])}
	seed := space.Signing.Seed()
	asDecimals := fmt.Sprintf("%d %d %d %d", seed[0], seed[1], seed[2], seed[3]) // how %v prints bytes
	for _, v := range []any{space, keys, node, &space, &keys} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(format, v)
			for _, s := range secrets {
				if strings.Contains(out, s) || strings.Contains(out, asDecimals) {
					t.Errorf("%s of %T prints a private key: %s", format, v, out)
				}
			}
		}
	}
}

func TestLoadKeysChecksTheSpaceFilesMatch(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	if _, err := GenerateSpace(dir, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateSpace(other, other); err != nil {
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

func TestKeyFileErrorsNameTheirLocation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	id := `node-id: "0102030405060708"` + "\n"
	key := strings.Repeat("11", 32)
	for _, tt := range []struct {
		file, content, want string
		pub                 bool
	}{
		{"a.key", id + "map-key: 00\nwireguard-key: " + key + "\n", "a.key:2:10: map-key: node private key must be 32 hex bytes", false},
		{"b.key", id + "map-key: " + key + "\nwireguard-key: " + key + "\nextra: 1\n", `b.key:4:8: unknown field "extra"`, false},
		{"c.key", id + "map-key: " + key + "\n", "c.key: wireguard-key is missing", false},
		{"d.key", `node-id: "0000000000000000"` + "\nmap-key: " + key + "\nwireguard-key: " + key + "\n", "d.key:1:10: node-id is zero", false},
		{"e.pub", id + "map-key: " + strings.Repeat("00", 32) + "\nwireguard-key: " + key + "\n", "e.pub:2:10: map-key: node public key", true}, // low-order
		{"f.key", id + "map-key: [1]\nwireguard-key: " + key + "\n", "f.key:2:10: expected a single value", false},
	} {
		path := write(tt.file, tt.content)
		var err error
		if tt.pub {
			_, err = ReadNodePublic(path)
		} else {
			_, err = ReadNodeKey(path)
		}
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v\nwant %q", tt.file, err, tt.want)
		}
	}

	// Hex that YAML would take for a number is read as written.
	digits, float := strings.Repeat("12", 32), "1e"+strings.Repeat("0", 62)
	k, err := ReadNodeKey(write("g.key", "node-id: 1234567812345678\nmap-key: "+digits+"\nwireguard-key: "+float+"\n"))
	if err != nil || hex.EncodeToString(k.Map[:]) != digits || hex.EncodeToString(k.WireGuard[:]) != float || k.ID.String() != "1234567812345678" {
		t.Errorf("numeric-looking hex: %v", err)
	}
	if _, err := netmap.ParseNodeID(k.ID.String()); err != nil {
		t.Fatal(err)
	}
}
