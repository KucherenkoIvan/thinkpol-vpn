package dns

import (
	"strings"
	"testing"
)

// Output as scutil prints it.
const showDNS = `<dictionary> {
  DomainName : lan
  SearchOrder : 1
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : fd00::1
  }
}
`

func TestScutilShowIsParsed(t *testing.T) {
	d, ok, err := parseShow(showDNS)
	if err != nil || !ok || d.opaque {
		t.Fatalf("%+v %v %v", d, ok, err)
	}
	if d.strs["DomainName"] != "lan" || d.strs["SearchOrder"] != "1" || strings.Join(d.array("ServerAddresses"), ",") != "192.168.1.1,fd00::1" {
		t.Errorf("%+v", d)
	}
	if _, ok, err := parseShow("  No such key\n"); ok || err != nil {
		t.Errorf("no such key: %v %v", ok, err)
	}
	nested := `<dictionary> {
  Options : <dictionary> {
    A : 1
  }
  ServerAddresses : <array> {
    0 : 10.0.0.1
  }
  Blob : <data> 0x0102
}
`
	d, ok, err = parseShow(nested)
	if err != nil || !ok || !d.opaque || d.array("ServerAddresses")[0] != "10.0.0.1" {
		t.Errorf("nested: %+v %v %v", d, ok, err)
	}
	// A value that is the empty string prints "Key : " (seen for an empty
	// DomainName): parsed as "", not a failed read.
	empty := "<dictionary> {\n  DomainName : \n  SearchOrder : 1\n}\n"
	d, ok, err = parseShow(empty)
	if err != nil || !ok || d.opaque || d.strs["DomainName"] != "" || d.strs["SearchOrder"] != "1" {
		t.Errorf("empty value: %+v %v %v", d, ok, err)
	}
	// A value that contains the phrase is present, not missing.
	phrased := "<dictionary> {\n  DomainName : No such key\n}\n"
	d, ok, err = parseShow(phrased)
	if err != nil || !ok || d.opaque || d.strs["DomainName"] != "No such key" {
		t.Errorf("a value with the phrase: %+v %v %v", d, ok, err)
	}
	for _, bad := range []string{"garbage", "<dictionary> {\n  A : b\n"} {
		if _, _, err := parseShow(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestScutilListIsParsed(t *testing.T) {
	out := "  subKey [0] = State:/Network/Service/A/DNS\n  subKey [1] = State:/Network/Service/B/IPv4\n"
	keys, err := parseList(out)
	if err != nil || strings.Join(keys, ",") != "State:/Network/Service/A/DNS,State:/Network/Service/B/IPv4" {
		t.Errorf("%v, %v", keys, err)
	}
	if keys, err := parseList("  no keys.\n"); err != nil || len(keys) != 0 {
		t.Errorf("%v, %v", keys, err)
	}
	// scutil answers a command it doesn't know in text and exits 0: a
	// failed listing, not an empty one.
	failed := "frobnicate: unknown, type \"help\" for command info\n"
	if keys, err := parseList(failed); err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("%v, %v", keys, err)
	}
	// A subKey line without a key is malformed, not a key.
	if _, err := parseList("  subKey [0] =\n"); err == nil {
		t.Error("a keyless subKey line: no error")
	}
	// Real scutil prints "  no keys." for none: completely empty output
	// is a failed listing, not an empty one.
	for _, out := range []string{"", "  \n"} {
		if _, err := parseList(out); err == nil {
			t.Errorf("%q: no error", out)
		}
	}
}

// What SetSystem writes reads back the same, numbers as numbers.
func TestScutilSetScript(t *testing.T) {
	d, _, _ := parseShow(showDNS)
	d.strs[overrideProp] = "1"
	got, err := setScript("State:/Network/Service/A/DNS", d)
	if err != nil {
		t.Fatal(err)
	}
	want := "d.init\nd.add DomainName lan\nd.add SearchOrder # 1\nd.add ThinkpolOverride 1\nd.add ServerAddresses * 192.168.1.1 fd00::1\nset State:/Network/Service/A/DNS\n"
	if got != want {
		t.Errorf("script:\n%s\nwant:\n%s", got, want)
	}
	// Nothing that would split into several tokens, or inject a command.
	for _, v := range []string{"a b", "x\nquit", `"q"`} {
		d := newDict()
		d.strs["DomainName"] = v
		if _, err := setScript("State:/Network/Service/A/DNS", d); err == nil {
			t.Errorf("%q: no error", v)
		}
	}
	// An empty string value goes as "", an empty number can't be.
	empty := newDict()
	empty.strs["DomainName"] = ""
	script, err := setScript("State:/Network/Service/A/DNS", empty)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `d.add DomainName ""`+"\n") {
		t.Errorf("script:\n%s", script)
	}
	emptyNumber := newDict()
	emptyNumber.strs["SearchOrder"] = ""
	if _, err := setScript("State:/Network/Service/A/DNS", emptyNumber); err == nil {
		t.Error("an empty number: no error")
	}
	if _, err := setScript("State:/Network/Service/A/DNS\nremove X", newDict()); err == nil {
		t.Error("a key with a newline: no error")
	}
	opaque := newDict()
	opaque.opaque = true
	if _, err := setScript("K", opaque); err == nil {
		t.Error("an opaque dict: no error")
	}
}

// An empty string in an array (an empty supplemental match domain, the
// node's default resolver) goes to scutil as "" and comes back as it
// prints it, "0 : ".
func TestAnEmptyStringRoundTrips(t *testing.T) {
	d := newDict()
	d.arrays["SupplementalMatchDomains"] = []string{""}
	d.strs["SearchOrder"] = "100000"
	script, err := setScript("State:/Network/Service/X/DNS", d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "d.add SupplementalMatchDomains * \"\"\n") || !strings.Contains(script, "d.add SearchOrder # 100000\n") {
		t.Errorf("script:\n%s", script)
	}
	// What scutil prints for it (d.show of that script, seen on a Mac).
	shown := "<dictionary> {\n  SearchOrder : 100000\n  SupplementalMatchDomains : <array> {\n    0 : \n  }\n}\n"
	got, ok, err := parseShow(shown)
	if err != nil || !ok || got.opaque || !got.equal(d) {
		t.Errorf("parsed %+v %v %v", got, ok, err)
	}
	// An empty string value goes as "" too, and reads back as scutil
	// prints it ("Key : ", seen for an empty DomainName).
	str := newDict()
	str.strs["DomainName"] = ""
	script, err = setScript("State:/Network/Service/X/DNS", str)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `d.add DomainName ""`+"\n") {
		t.Errorf("script:\n%s", script)
	}
	got, ok, err = parseShow("<dictionary> {\n  DomainName : \n}\n")
	if err != nil || !ok || got.opaque || !got.equal(str) {
		t.Errorf("parsed %+v %v %v", got, ok, err)
	}
}
