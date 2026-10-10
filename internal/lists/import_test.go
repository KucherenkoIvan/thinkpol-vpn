package lists

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// v2flyEntry is one GeoIP message of a geoip.dat fixture.
type v2flyFixture struct {
	code    string
	cidrs   []string
	reverse bool
	extra   bool // add fields a reader must skip
}

// v2flyDat encodes a GeoIPList the way v2fly's tools do (field numbers from
// v2ray-core's app/router/config.proto).
func v2flyDat(entries ...v2flyFixture) []byte {
	var list []byte
	for _, e := range entries {
		var msg []byte
		msg = protowire.AppendTag(msg, 1, protowire.BytesType)
		msg = protowire.AppendString(msg, e.code)
		for _, c := range e.cidrs {
			p := netip.MustParsePrefix(c)
			var cidr []byte
			cidr = protowire.AppendTag(cidr, 1, protowire.BytesType)
			cidr = protowire.AppendBytes(cidr, p.Addr().AsSlice())
			cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
			cidr = protowire.AppendVarint(cidr, uint64(p.Bits()))
			if e.extra {
				cidr = protowire.AppendTag(cidr, 9, protowire.Fixed32Type)
				cidr = protowire.AppendFixed32(cidr, 7)
			}
			msg = protowire.AppendTag(msg, 2, protowire.BytesType)
			msg = protowire.AppendBytes(msg, cidr)
		}
		if e.reverse {
			msg = protowire.AppendTag(msg, 3, protowire.VarintType)
			msg = protowire.AppendVarint(msg, 1)
		}
		if e.extra {
			msg = protowire.AppendTag(msg, 15, protowire.BytesType)
			msg = protowire.AppendString(msg, "ignored")
			msg = protowire.AppendTag(msg, 16, protowire.Fixed64Type)
			msg = protowire.AppendFixed64(msg, 1)
		}
		list = protowire.AppendTag(list, 1, protowire.BytesType)
		list = protowire.AppendBytes(list, msg)
	}
	return list
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func importOK(t *testing.T, src []byte, f Format, only ...string) map[string][]string {
	t.Helper()
	got, err := Import(bytes.NewReader(src), f, only)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, l := range BuildAll(got) {
		out[l.Name] = strs(l.Set.Prefixes())
	}
	return out
}

// The same addresses from both sources: what the importers must agree on.
var (
	fixtureV2fly = []v2flyFixture{
		{code: "RU", cidrs: []string{"5.3.0.0/17", "5.3.128.0/17", "77.88.8.0/24", "2a02:6b8::/32"}},
		{code: "BY", cidrs: []string{"37.17.0.0/17"}, extra: true},
		{code: "ru", cidrs: []string{"77.88.8.8/32", "2a02:6b8:8000::/33"}},                    // merges into RU
		{code: "PRIVATE", cidrs: []string{"10.0.0.0/8", "fc00::/7", "::ffff:192.168.0.0/112"}}, // the mapped one is left out
	}
	fixtureDBIP = strings.Join([]string{
		"0.0.0.0,0.255.255.255,ZZ",
		"5.3.0.0,5.3.255.255,RU",
		"37.17.0.0,37.17.127.255,BY",
		"77.88.8.0,77.88.8.255,RU",
		"::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ", // as in DB-IP: covers ::ffff:0:0/96
		"2a02:6b8::,2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff,RU",
	}, "\n") + "\n"
	wantRU = []string{"5.3.0.0/16", "77.88.8.0/24", "2a02:6b8::/32"}
	wantBY = []string{"37.17.0.0/17"}
)

func TestImportV2fly(t *testing.T) {
	dat := v2flyDat(fixtureV2fly...)
	for _, src := range [][]byte{dat, gz(t, dat)} {
		got := importOK(t, src, FormatV2flyGeoIP)
		if !slices.Equal(got["ru"], wantRU) || !slices.Equal(got["by"], wantBY) || len(got) != 3 ||
			!slices.Equal(got["private"], []string{"10.0.0.0/8", "fc00::/7"}) {
			t.Fatalf("got %v", got)
		}
	}
	got := importOK(t, dat, FormatV2flyGeoIP, "by")
	if len(got) != 1 || !slices.Equal(got["by"], wantBY) {
		t.Fatalf("only by: %v", got)
	}
}

func TestImportDBIP(t *testing.T) {
	for _, src := range [][]byte{[]byte(fixtureDBIP), gz(t, []byte(fixtureDBIP))} {
		got := importOK(t, src, FormatDBIPCSV)
		if !slices.Equal(got["ru"], wantRU) || !slices.Equal(got["by"], wantBY) || len(got) != 3 ||
			!slices.Equal(got["zz"], []string{"0.0.0.0/8"}) {
			t.Fatalf("got %v", got)
		}
	}
}

// TestSameInputSameHash is the acceptance check: the same input built
// twice, and the same addresses from either source, give the same hash.
func TestSameInputSameHash(t *testing.T) {
	hash := func(src []byte, f Format) [32]byte {
		got, err := Import(bytes.NewReader(src), f, []string{"ru"})
		if err != nil {
			t.Fatal(err)
		}
		return BuildAll(got)[0].SHA256
	}
	dat := v2flyDat(fixtureV2fly...)
	a, b := hash(dat, FormatV2flyGeoIP), hash(slices.Clone(dat), FormatV2flyGeoIP)
	c, d := hash([]byte(fixtureDBIP), FormatDBIPCSV), hash(gz(t, []byte(fixtureDBIP)), FormatDBIPCSV)
	slices.Reverse(fixtureV2fly)
	e := hash(v2flyDat(fixtureV2fly...), FormatV2flyGeoIP)
	slices.Reverse(fixtureV2fly)
	if a != b || a != c || a != d || a != e {
		t.Fatalf("hashes differ: %x %x %x %x %x", a, b, c, d, e)
	}
}

func TestImportErrors(t *testing.T) {
	cases := []struct {
		name string
		src  []byte
		f    Format
		only []string
		want error
	}{
		{"missing list", v2flyDat(fixtureV2fly...), FormatV2flyGeoIP, []string{"ru", "kz"}, ErrUnknownName},
		{"missing list, dbip", []byte(fixtureDBIP), FormatDBIPCSV, []string{"de"}, ErrUnknownName},
		{"bad requested name", []byte(fixtureDBIP), FormatDBIPCSV, []string{"RU"}, nil},
		{"reverse match kept", v2flyDat(v2flyFixture{code: "RU", cidrs: []string{"1.0.0.0/8"}, reverse: true}), FormatV2flyGeoIP, nil, nil},
		{"bad name", v2flyDat(v2flyFixture{code: "geolocation-!cn", cidrs: []string{"1.0.0.0/8"}}), FormatV2flyGeoIP, nil, nil},
		{"truncated protobuf", v2flyDat(fixtureV2fly...)[:20], FormatV2flyGeoIP, nil, nil},
		{"5-byte ip", v2flyCIDR("RU", []byte{1, 2, 3, 4, 5}, 8), FormatV2flyGeoIP, nil, nil},
		{"prefix too long", v2flyCIDR("RU", []byte{1, 2, 3, 4}, 33), FormatV2flyGeoIP, nil, nil},
		{"no address", v2flyCIDR("RU", nil, 8), FormatV2flyGeoIP, nil, nil},
		{"dbip mixed families", []byte("1.0.0.0,::1,RU\n"), FormatDBIPCSV, nil, ErrInvalidPrefix},
		{"dbip reversed", []byte("1.0.0.9,1.0.0.0,RU\n"), FormatDBIPCSV, nil, ErrInvalidPrefix},
		{"dbip bad address", []byte("1.0.0,1.0.0.9,RU\n"), FormatDBIPCSV, nil, nil},
		{"dbip zone", []byte("fe80::1%eth0,fe80::2,RU\n"), FormatDBIPCSV, nil, ErrInvalidPrefix},
		{"dbip two fields", []byte("1.0.0.0,1.0.0.9\n"), FormatDBIPCSV, nil, nil},
		{"dbip bad name", []byte("1.0.0.0,1.0.0.9,R U\n"), FormatDBIPCSV, nil, nil},
		{"unknown format", []byte(fixtureDBIP), Format("mmdb"), nil, nil},
		{"broken gzip", []byte{0x1f, 0x8b, 0, 0}, FormatDBIPCSV, nil, nil},
	}
	for _, c := range cases {
		_, err := Import(bytes.NewReader(c.src), c.f, c.only)
		if err == nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// An entry nobody asked for is skipped unchecked.
	src0 := v2flyDat(v2flyFixture{code: "geolocation-!cn", cidrs: []string{"1.0.0.0/8"}}, fixtureV2fly[1])
	if _, err := Import(bytes.NewReader(src0), FormatV2flyGeoIP, []string{"by"}); err != nil {
		t.Errorf("skipped bad name: %v", err)
	}
	// A reversed entry nobody asked for is skipped, not an error.
	src := v2flyDat(v2flyFixture{code: "RU", cidrs: []string{"1.0.0.0/8"}, reverse: true}, fixtureV2fly[1])
	if _, err := Import(bytes.NewReader(src), FormatV2flyGeoIP, []string{"by"}); err != nil {
		t.Errorf("skipped reverse entry: %v", err)
	}
}

func v2flyCIDR(code string, ip []byte, bits int) []byte {
	var cidr []byte
	cidr = protowire.AppendTag(cidr, 1, protowire.BytesType)
	cidr = protowire.AppendBytes(cidr, ip)
	if bits >= 0 {
		cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
		cidr = protowire.AppendVarint(cidr, uint64(bits))
	}
	var msg []byte
	msg = protowire.AppendTag(msg, 1, protowire.BytesType)
	msg = protowire.AppendString(msg, code)
	msg = protowire.AppendTag(msg, 2, protowire.BytesType)
	msg = protowire.AppendBytes(msg, cidr)
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), msg)
}

func TestImportStopsAtSizeCap(t *testing.T) {
	defer func(n int64) { maxSourceSize = n }(maxSourceSize)
	maxSourceSize = 64
	big := []byte(strings.Repeat("1.0.0.0,1.0.0.255,RU\n", 10))
	for _, src := range [][]byte{big, gz(t, big)} {
		if _, err := Import(bytes.NewReader(src), FormatDBIPCSV, nil); !errors.Is(err, errSourceTooLarge) {
			t.Errorf("over the cap: %v", err)
		}
		if _, err := Import(bytes.NewReader(src), FormatV2flyGeoIP, nil); !errors.Is(err, errSourceTooLarge) {
			t.Errorf("over the cap: %v", err)
		}
	}
	if _, err := Import(bytes.NewReader(big[:63]), FormatDBIPCSV, nil); err != nil {
		t.Errorf("under the cap: %v", err)
	}
}

func TestFormatFromPath(t *testing.T) {
	for path, want := range map[string]Format{
		"geoip.dat":                     FormatV2flyGeoIP,
		"dir/GeoIP.DAT.gz":              FormatV2flyGeoIP,
		"dbip-country-lite-2026-10.csv": FormatDBIPCSV,
		"dbip.csv.gz":                   FormatDBIPCSV,
		"x.mmdb":                        "",
		"csv":                           "",
	} {
		got, err := FormatFromPath(path)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("%s: %q, %v", path, got, err)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"ru", "private", "zz", "a", "cloudflare-ipv6", strings.Repeat("a", 32)} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "RU", "-ru", "r u", "geolocation-!cn", strings.Repeat("a", 33), "ру"} {
		if CheckName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// FuzzImportV2fly: a geoip.dat is a downloaded file; no input may panic.
func FuzzImportV2fly(f *testing.F) {
	f.Add(v2flyDat(fixtureV2fly...))
	f.Add(v2flyCIDR("RU", []byte{1, 2, 3, 4}, 33))
	f.Fuzz(func(t *testing.T, src []byte) {
		lists, err := Import(bytes.NewReader(src), FormatV2flyGeoIP, nil)
		if err != nil {
			return
		}
		for _, l := range BuildAll(lists) {
			if CheckName(l.Name) != nil {
				t.Fatalf("bad name %q", l.Name)
			}
			if _, err := Decode(l.Blob); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// TestImportLeavesOutMappedIPv6: IPv6 entries are never unmapped into IPv4;
// those overlapping ::ffff:0:0/96 are counted and left out.
func TestImportLeavesOutMappedIPv6(t *testing.T) {
	check := func(lists map[string]*Builder, name string, want []string) {
		t.Helper()
		set, st := lists[name].Build()
		if got := strs(set.Prefixes()); !slices.Equal(got, want) || st.Skipped != 1 {
			t.Fatalf("%s: %v, stats %+v", name, got, st)
		}
		if set.Contains(addr("192.168.1.1")) || set.Contains(addr("1.2.3.4")) {
			t.Fatalf("%s: a mapped entry leaked into IPv4", name)
		}
	}
	v2, err := Import(bytes.NewReader(v2flyDat(fixtureV2fly...)), FormatV2flyGeoIP, nil)
	if err != nil {
		t.Fatal(err)
	}
	check(v2, "private", []string{"10.0.0.0/8", "fc00::/7"})
	db, err := Import(strings.NewReader(fixtureDBIP), FormatDBIPCSV, nil)
	if err != nil {
		t.Fatal(err)
	}
	check(db, "zz", []string{"0.0.0.0/8"})
}

// TestV2flyMissingPrefixIsZero: proto3 omits a zero prefix length.
func TestV2flyMissingPrefixIsZero(t *testing.T) {
	got := importOK(t, v2flyCIDR("RU", []byte{1, 2, 3, 4}, -1), FormatV2flyGeoIP)
	if !slices.Equal(got["ru"], []string{"0.0.0.0/0"}) {
		t.Fatalf("got %v", got)
	}
}

func TestImportStopsAtEntryCap(t *testing.T) {
	defer func(n int) { maxEntries = n }(maxEntries)
	maxEntries = 3
	csv3 := "1.0.0.0,1.0.0.255,RU\n2.0.0.0,2.0.0.255,DE\n3.0.0.0,3.0.0.255,RU\n"
	if _, err := Import(strings.NewReader(csv3), FormatDBIPCSV, nil); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	// Rows of lists not kept count too.
	if _, err := Import(strings.NewReader(csv3+"4.0.0.0,4.0.0.255,DE\n"), FormatDBIPCSV, []string{"ru"}); !errors.Is(err, errTooManyEntries) {
		t.Fatalf("over the cap: %v", err)
	}
	dat := v2flyDat(v2flyFixture{code: "RU", cidrs: []string{"1.0.0.0/8", "2.0.0.0/8"}}, v2flyFixture{code: "BY", cidrs: []string{"3.0.0.0/8", "4.0.0.0/8"}})
	if _, err := Import(bytes.NewReader(dat), FormatV2flyGeoIP, []string{"ru"}); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	if _, err := Import(bytes.NewReader(dat), FormatV2flyGeoIP, nil); !errors.Is(err, errTooManyEntries) {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestAttribution(t *testing.T) {
	if a := FormatDBIPCSV.Attribution(); !strings.Contains(a, "IP Geolocation by DB-IP (CC BY 4.0)") {
		t.Errorf("dbip: %q", a)
	}
	if a := FormatV2flyGeoIP.Attribution(); !strings.Contains(a, "CC BY-SA 4.0") || !strings.Contains(a, "GeoLite2") {
		t.Errorf("v2fly: %q", a)
	}
	if Format("x").Attribution() != "" {
		t.Error("unknown format attributed")
	}
}
