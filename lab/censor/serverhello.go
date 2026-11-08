package censor

import (
	"crypto/md5" //nolint:gosec // JA3S is defined as an MD5 hash
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// TLS extensions a ServerHello's fingerprint reads.
const (
	tlsExtALPN              = 16
	tlsExtSupportedVersions = 43
)

// serverHello is what JA3S and JA4S read of a server's hello (RFC 8446
// section 4.1.3).
type serverHello struct {
	legacyVersion uint16
	// version is the one supported_versions selects, else legacyVersion.
	version    uint16
	cipher     uint16
	extensions []uint16 // in the order sent
	// alpn is the protocol the ServerHello selects: TLS 1.2 and earlier
	// only; TLS 1.3 sends it encrypted.
	alpn string
}

// serverHelloOf reads the ServerHello at a server stream's start, whole
// however many records and segments carried it: errIncomplete until it
// has arrived, errNotServerHello for anything else.
func serverHelloOf(b []byte) (serverHello, error) {
	msg, _, err := helloMessage(b, tlsServerHello)
	if err != nil {
		return serverHello{}, err
	}
	return parseServerHello(msg)
}

func parseServerHello(body []byte) (serverHello, error) {
	var h serverHello
	r := reader(body)
	var ok bool
	if h.legacyVersion, ok = r.uint16(); !ok || !r.skip(32) { // random
		return h, errNotServerHello
	}
	if _, ok = r.vector8(); !ok { // legacy_session_id_echo
		return h, errNotServerHello
	}
	if h.cipher, ok = r.uint16(); !ok || !r.skip(1) { // legacy_compression_method
		return h, errNotServerHello
	}
	h.version = h.legacyVersion
	if len(r) == 0 {
		return h, nil // no extensions (TLS 1.2 allows it)
	}
	exts, ok := r.vector16()
	if !ok || len(r) != 0 {
		return h, errNotServerHello
	}
	for len(exts) > 0 {
		typ, ok := exts.uint16()
		if !ok {
			return h, errNotServerHello
		}
		data, ok := exts.vector16()
		if !ok {
			return h, errNotServerHello
		}
		h.extensions = append(h.extensions, typ)
		switch typ {
		case tlsExtSupportedVersions:
			if h.version, ok = data.uint16(); !ok {
				return h, errNotServerHello
			}
		case tlsExtALPN:
			list, ok := data.vector16()
			if !ok {
				return h, errNotServerHello
			}
			name, ok := list.vector8()
			if !ok {
				return h, errNotServerHello
			}
			h.alpn = string(name)
		}
	}
	return h, nil
}

// isGREASE reports a GREASE value (RFC 8701), which JA3S leaves out.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ja3sString is JA3S before its hash: the legacy version, the cipher and
// the extensions in order, in decimal ("771,4865,43-51").
func (h serverHello) ja3sString() string {
	var exts []string
	for _, e := range h.extensions {
		if !isGREASE(e) {
			exts = append(exts, strconv.Itoa(int(e)))
		}
	}
	return fmt.Sprintf("%d,%d,%s", h.legacyVersion, h.cipher, strings.Join(exts, "-"))
}

// ja3s is JA3S: the MD5 of ja3sString, in hex.
func (h serverHello) ja3s() string {
	sum := md5.Sum([]byte(h.ja3sString())) //nolint:gosec // JA3S is defined as an MD5 hash
	return hex.EncodeToString(sum[:])
}

// ja4s is FoxIO's JA4S over TCP: "t", the version, the number of
// extensions and the selected ALPN's first and last characters; the
// cipher; the first 12 hex digits of the SHA-256 of the extensions in
// order ("t130200_1301_234ea6891581").
func (h serverHello) ja4s() string {
	extHash := "000000000000"
	if len(h.extensions) > 0 {
		hexes := make([]string, len(h.extensions))
		for i, e := range h.extensions {
			hexes[i] = fmt.Sprintf("%04x", e)
		}
		sum := sha256.Sum256([]byte(strings.Join(hexes, ",")))
		extHash = hex.EncodeToString(sum[:])[:12]
	}
	return fmt.Sprintf("t%s%02d%s_%04x_%s", ja4Version(h.version), min(len(h.extensions), 99), ja4ALPN(h.alpn), h.cipher, extHash)
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// ja4ALPN is JA4's two ALPN characters: the first and last of the
// protocol, "00" for none, and the first and last hex digits of it when
// either character isn't alphanumeric.
func ja4ALPN(alpn string) string {
	if alpn == "" {
		return "00"
	}
	first, last := alpn[0], alpn[len(alpn)-1]
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte(alpn))
		return h[:1] + h[len(h)-1:]
	}
	return string([]byte{first, last})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// String says everything the fingerprints are made of, for a verdict
// log's reason.
func (h serverHello) String() string {
	alpn := h.alpn
	if alpn == "" {
		alpn = "none"
	}
	return fmt.Sprintf("JA4S %s, JA3S %s (%s), extensions %v, ALPN %s", h.ja4s(), h.ja3s(), h.ja3sString(), h.extensions, alpn)
}

// differences lists how h differs from want, the site's: empty when the
// fingerprints match.
func (h serverHello) differences(want serverHello) []string {
	var d []string
	if h.version != want.version || h.legacyVersion != want.legacyVersion {
		d = append(d, fmt.Sprintf("version %#04x (legacy %#04x), the site's %#04x (legacy %#04x)", h.version, h.legacyVersion, want.version, want.legacyVersion))
	}
	if h.cipher != want.cipher {
		d = append(d, fmt.Sprintf("cipher %#04x, the site's %#04x", h.cipher, want.cipher))
	}
	if !slices.Equal(h.extensions, want.extensions) {
		d = append(d, fmt.Sprintf("extensions %v, the site's %v", h.extensions, want.extensions))
	}
	if h.alpn != want.alpn {
		d = append(d, fmt.Sprintf("ALPN %q, the site's %q", h.alpn, want.alpn))
	}
	return d
}
