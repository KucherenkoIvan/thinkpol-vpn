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
