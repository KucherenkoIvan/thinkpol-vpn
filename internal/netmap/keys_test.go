package netmap

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestKeysAndIDsRoundTrip(t *testing.T) {
	// RFC 7748, section 6.1: Alice's X25519 key pair.
	alice, err := ParseNodePrivateKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}
	if got := alice.Public().String(); got != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("Public() = %s, not the X25519 public key", got)
	}

	key, other := GenerateNodeKey(), GenerateNodeKey()
	n1, n2 := NewNodeID(), NewNodeID()
	s1, s2 := NewSpaceID(), NewSpaceID()
	if key == other || n1 == n2 || s1 == s2 || n1.IsZero() || s1.IsZero() {
		t.Fatal("generated values repeat or are zero")
	}

	space, node := NewSpaceID(), NewNodeID()
	if got, err := ParseSpaceID(space.String()); err != nil || got != space {
		t.Errorf("ParseSpaceID(%v) = %v, %v", space, got, err)
	}
	if got, err := ParseNodeID(node.String()); err != nil || got != node {
		t.Errorf("ParseNodeID(%v) = %v, %v", node, got, err)
	}
	if got, err := ParseNodePublicKey(key.Public().String()); err != nil || got != key.Public() {
		t.Errorf("ParseNodePublicKey = %v, %v", got, err)
	}
	if got, err := ParseNodePrivateKey(hex.EncodeToString(key[:])); err != nil || got != key {
		t.Errorf("ParseNodePrivateKey failed: %v", err)
	}
	wg := WireGuardKey(GenerateNodeKey().Public())
	if got, err := ParseWireGuardKey(wg.String()); err != nil || got != wg {
		t.Errorf("ParseWireGuardKey = %v, %v", got, err)
	}

	for _, bad := range []string{"", "zz", node.String() + "00", node.String()[2:], space.String()} {
		if _, err := ParseNodeID(bad); err == nil {
			t.Errorf("ParseNodeID(%q) accepted", bad)
		}
	}
}

func TestPrivateKeyIsRedacted(t *testing.T) {
	key := GenerateNodeKey()
	secret := hex.EncodeToString(key[:])
	for _, format := range []string{"%v", "%s", "%x", "%#v", "%+v"} {
		out := fmt.Sprintf(format, key)
		if strings.Contains(out, secret) || strings.Contains(out, fmt.Sprint(key[0], " ", key[1])) {
			t.Errorf("%s prints the key: %s", format, out)
		}
	}
	if out := fmt.Sprintf("%+v", struct{ K NodePrivateKey }{key}); strings.Contains(out, secret) {
		t.Errorf("a struct holding the key prints it: %s", out)
	}
}

func TestNodePublicKeyCheck(t *testing.T) {
	// The canonical low-order points of Curve25519 (as in libsodium's
	// blocklist), the same with the top bit set, and values at or above p.
	bad := map[string]string{
		"u = 0":                    "0000000000000000000000000000000000000000000000000000000000000000",
		"u = 1":                    "0100000000000000000000000000000000000000000000000000000000000000",
		"order 8 (a)":              "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"order 8 (b)":              "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"u = p - 1":                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u = p":                    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u = p + 1":                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u = 2^255 - 1":            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"u = 0, top bit set":       "0000000000000000000000000000000000000000000000000000000000000080",
		"u = 1, top bit set":       "0100000000000000000000000000000000000000000000000000000000000080",
		"order 8 (b), top bit set": "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	}
	for name, s := range bad {
		if _, err := ParseNodePublicKey(s); err == nil {
			t.Errorf("%s: ParseNodePublicKey accepted %s", name, s)
		}
	}
	// A valid key with the top bit set is still refused: honest keys never
	// have it, and accepting it would give one point two encodings.
	valid := GenerateNodeKey().Public()
	topBit := valid
	topBit[31] |= 0x80
	if err := topBit.Check(); err == nil {
		t.Error("a key with the top bit set passed Check")
	}
	for range 100 {
		k := GenerateNodeKey().Public()
		if err := k.Check(); err != nil {
			t.Fatalf("a generated key failed Check: %v", err)
		}
		if _, err := ParseNodePublicKey(k.String()); err != nil {
			t.Fatalf("ParseNodePublicKey(%v): %v", k, err)
		}
	}
	// u = p - 2 is reduced and not low-order: the bound is exact.
	if _, err := ParseNodePublicKey("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); err != nil {
		t.Errorf("u = p - 2 refused: %v", err)
	}
}
