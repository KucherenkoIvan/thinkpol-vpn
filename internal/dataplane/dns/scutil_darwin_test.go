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
	for _, bad := range []string{"garbage", "<dictionary> {\n  A : b\n"} {
		if _, _, err := parseShow(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestScutilListIsParsed(t *testing.T) {
	out := "  subKey [0] = State:/Network/Service/A/DNS\n  subKey [1] = State:/Network/Service/B/IPv4\n"
	if got := parseList(out); strings.Join(got, ",") != "State:/Network/Service/A/DNS,State:/Network/Service/B/IPv4" {
		t.Errorf("%v", got)
	}
	if got := parseList("  no keys.\n"); len(got) != 0 {
		t.Errorf("%v", got)
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
	for _, v := range []string{"a b", "x\nquit", "", `"q"`} {
		d := newDict()
		d.strs["DomainName"] = v
		if _, err := setScript("State:/Network/Service/A/DNS", d); err == nil {
			t.Errorf("%q: no error", v)
		}
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
