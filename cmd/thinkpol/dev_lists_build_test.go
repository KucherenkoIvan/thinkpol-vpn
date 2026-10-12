package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

const dbipFixture = "5.3.0.0,5.3.255.255,RU\n" +
	"37.17.0.0,37.17.127.255,BY\n" +
	"77.88.8.0,77.88.8.255,RU\n" +
	"::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ\n" +
	"2a02:6b8::,2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff,RU\n"

func TestDevListsBuild(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dbip-country-lite.csv")
	if err := os.WriteFile(src, []byte(dbipFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")

	var first []byte
	for range 2 {
		code, stdout, stderr := runCLI(t, "dev", "lists", "build", "-only", "RU", "-out", out, src)
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		blob, err := os.ReadFile(filepath.Join(out, "ru.geoip"))
		if err != nil {
			t.Fatal(err)
		}
		set, err := lists.Decode(blob)
		if err != nil || len(set.Prefixes()) != 3 {
			t.Fatalf("blob: %v %v", set.Prefixes(), err)
		}
		// name, sha256, bytes, then entries in and prefixes out per family:
		// two RU ranges for IPv4, one for IPv6.
		row := fmt.Sprintf("ru %x %d 2 2 1 1", sha256.Sum256(blob), len(blob))
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 4 || strings.Join(strings.Fields(lines[1]), " ") != row ||
			lines[2] != "" || !strings.HasPrefix(lines[3], "IP Geolocation by DB-IP (CC BY 4.0)") {
			t.Fatalf("stdout %q, want a row %q and the attribution", stdout, row)
		}
		if stderr != "" {
			t.Fatalf("stderr %q", stderr)
		}
		if first != nil && string(first) != string(blob) {
			t.Fatal("second build differs")
		}
		first = blob
	}
	if _, err := os.Stat(filepath.Join(out, "by.geoip")); !os.IsNotExist(err) {
		t.Fatalf("by.geoip written without being asked for: %v", err)
	}

	code, _, stderr := runCLI(t, "dev", "lists", "build", "-out", out, src)
	if code != 0 || !strings.Contains(stderr, "warning: zz: left out 1 IPv6 entries overlapping the IPv4-mapped range") {
		t.Fatalf("all lists: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(out, "by.geoip")); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"-only", "kz", "-out", out, src},
		{"-out", out, filepath.Join(dir, "missing.csv")},
		{"-out", out, filepath.Join(dir, "source.mmdb")},
		{"-format", "v2fly", "-out", out, src},
	} {
		if code, _, stderr := runCLI(t, append([]string{"dev", "lists", "build"}, args...)...); code != 1 {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if code, _, _ := runCLI(t, "dev", "lists", "build"); code != 2 {
		t.Errorf("no source: exit %d", code)
	}
}

// A list built by `dev lists build` goes into a hand-made map: the header
// lists it, the section of the node that uses it names it.
func TestDevMapBuildTakesLists(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dbip-country-lite.csv")
	if err := os.WriteFile(src, []byte(dbipFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRunCLI(t, "dev", "lists", "build", "-only", "ru", "-out", filepath.Join(dir, "lists"), src)
	blob, err := os.ReadFile(filepath.Join(dir, "lists", "ru.geoip"))
	if err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(spec, []byte(`lists:
  - {name: ru, file: lists/ru.geoip}
nodes:
  - {name: s, kind: server, ingress: true, endpoints: ["udp://192.0.2.1:4500"]}
  - {name: d, kind: device, lists: [ru]}
paths:
  - [d, s]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "s", "d")
	mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, spec)
	sum := fmt.Sprintf("sha256 %x, %d bytes", sha256.Sum256(blob), len(blob))
	if out := mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, mapFile); !strings.Contains(out, "blobs:\n  - geoip: "+sum) {
		t.Errorf("header:\n%s", out)
	}
	if out := mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, "d.key"), mapFile); !strings.Contains(out, "  - geoip ru: "+sum) {
		t.Errorf("d's section:\n%s", out)
	}

	if err := os.WriteFile(filepath.Join(dir, "lists", "ru.geoip"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, spec); code != 1 ||
		!strings.Contains(stderr, "spec.yaml:2:6: list ru: ") || !strings.Contains(stderr, "is not a GeoIP list blob") {
		t.Errorf("a junk list: exit %d, stderr %q", code, stderr)
	}
}
