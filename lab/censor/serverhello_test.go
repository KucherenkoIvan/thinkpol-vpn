package censor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// buildServerHello frames a ServerHello in one handshake record:
// extensions are type and data pairs, in order.
func buildServerHello(legacy, cipher uint16, exts ...[]byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, legacy)
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, 32)                             // session id echo
	body = append(body, bytes.Repeat([]byte{9}, 32)...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0) // compression
	if len(exts) > 0 {
		var all []byte
		for _, e := range exts {
			all = append(all, e...)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(all)))
		body = append(body, all...)
	}
	msg := append([]byte{tlsServerHello, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{tlsHandshake, 3, 3, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}

func ext(typ uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func alpnExt(proto string) []byte {
	list := append([]byte{byte(len(proto))}, proto...)
	return ext(tlsExtALPN, append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...))
}

// TestServerHelloFingerprints checks JA3S and JA4S against FoxIO's JA4S
// example (a TLS 1.3 hello, key_share then supported_versions) and a TLS
// 1.2 hello with ALPN, GREASE left out of JA3S only.
func TestServerHelloFingerprints(t *testing.T) {
	tls13 := buildServerHello(0x0303, 0x1301, ext(51, make([]byte, 36)), ext(tlsExtSupportedVersions, []byte{3, 4}))
	h, err := serverHelloOf(tls13)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.ja4s(), "t130200_1301_234ea6891581"; got != want {
		t.Errorf("JA4S %s, want FoxIO's %s", got, want)
	}
	if got, want := h.ja3sString(), "771,4865,51-43"; got != want {
		t.Errorf("JA3S string %s, want %s", got, want)
	}
	if got, want := h.ja3s(), "eb1d94daa7e0344597e756a1fb6e7054"; got != want {
		t.Errorf("JA3S %s, want %s", got, want)
	}

	tls12 := buildServerHello(0x0303, 0xc02f, ext(0xff01, []byte{0}), ext(0, nil), alpnExt("h2"), ext(23, nil), ext(0x1a1a, nil))
	h, err = serverHelloOf(tls12)
	if err != nil {
		t.Fatal(err)
	}
	if h.alpn != "h2" || h.version != 0x0303 {
		t.Errorf("TLS 1.2 hello: %+v", h)
	}
	if got, want := h.ja3sString(), "771,49199,65281-0-16-23"; got != want {
		t.Errorf("JA3S string %s, want %s (GREASE left out)", got, want)
	}
	if got := h.ja4s(); !strings.HasPrefix(got, "t1205h2_c02f_") {
		t.Errorf("JA4S %s, want t1205h2_c02f_…", got)
	}
	if got := ja4ALPN("x-y!"); got != "71" {
		t.Errorf("ALPN x-y! is %q in JA4, want the hex digits 71", got)
	}

	noExt, err := serverHelloOf(buildServerHello(0x0301, 0x002f))
	if err != nil || noExt.ja4s() != "t100000_002f_000000000000" {
		t.Errorf("a hello without extensions: %v %s", err, noExt.ja4s())
	}
}

// TestServerHelloReading: a hello split over segments is incomplete until
// whole, and one split over records is read; anything else is not one.
func TestServerHelloReading(t *testing.T) {
	b := buildServerHello(0x0303, 0x1301, ext(tlsExtSupportedVersions, []byte{3, 4}))
	for i := 0; i < len(b); i++ {
		if _, err := serverHelloOf(b[:i]); !errors.Is(err, errIncomplete) {
			t.Fatalf("first %d of %d bytes: %v, want incomplete", i, len(b), err)
		}
	}
	split := splitRecords(b, 10)
	if h, err := serverHelloOf(split); err != nil || h.version != 0x0304 {
		t.Errorf("over records: %+v %v", h, err)
	}
	if _, used, err := helloMessage(append(append([]byte(nil), split...), 0x14, 3, 3, 0, 1, 1), tlsServerHello); err != nil || used != len(split) {
		t.Errorf("used %d of %d bytes: %v", used, len(split), err)
	}
	for name, bad := range map[string][]byte{
		"a ClientHello": helloFor(t, "example.net"),
		"an alert":      {0x15, 3, 3, 0, 2, 2, 40},
		"random":        randomBytes(5, 100),
	} {
		if _, err := serverHelloOf(bad); !errors.Is(err, errNotServerHello) {
			t.Errorf("%s: %v, want not a ServerHello", name, err)
		}
	}
}

// TestServerHelloDifferences names every field that differs and nothing
// when the fingerprints match, the random and session id aside.
func TestServerHelloDifferences(t *testing.T) {
	a, _ := serverHelloOf(buildServerHello(0x0303, 0x1301, ext(43, []byte{3, 4}), ext(51, make([]byte, 36))))
	same, _ := serverHelloOf(buildServerHello(0x0303, 0x1301, ext(43, []byte{3, 4}), ext(51, make([]byte, 36))))
	if d := a.differences(same); len(d) != 0 {
		t.Errorf("same hello: %v", d)
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"cipher":          {buildServerHello(0x0303, 0x1302, ext(43, []byte{3, 4}), ext(51, make([]byte, 36))), "cipher"},
		"extension order": {buildServerHello(0x0303, 0x1301, ext(51, make([]byte, 36)), ext(43, []byte{3, 4})), "extensions"},
		"version":         {buildServerHello(0x0303, 0x1301, ext(51, make([]byte, 36))), "version"},
		"ALPN":            {buildServerHello(0x0303, 0x1301, ext(43, []byte{3, 4}), ext(51, make([]byte, 36)), alpnExt("h2")), "ALPN"},
	} {
		h, err := serverHelloOf(c.b)
		if err != nil {
			t.Fatal(err)
		}
		d := h.differences(a)
		if len(d) == 0 || !strings.Contains(strings.Join(d, ";"), c.want) {
			t.Errorf("%s: %v, want %s named", name, d, c.want)
		}
	}
}
