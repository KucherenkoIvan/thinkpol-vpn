package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Key files are a few `field: "value"` lines under comments, the layout
// `thinkpol dev keygen` writes: node.key holds node-id, map-key and
// wireguard-key (hex), space.pub holds space-id, signing-key and
// recovery-key (hex). This reader takes exactly that and nothing else.

// keyFields reads a key file's fields; every name in want must be there,
// once, and nothing else may be.
func keyFields(path string, data []byte, want ...string) (map[string]string, error) {
	fields := make(map[string]string, len(want))
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := fmt.Sprintf("%s:%d", path, i+1)
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%s: not a `field: value` line", at)
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		switch {
		case !slices.Contains(want, name):
			return nil, fmt.Errorf("%s: unknown field %q", at, name)
		case fields[name] != "":
			return nil, fmt.Errorf("%s: %s given twice", at, name)
		case value == "":
			return nil, fmt.Errorf("%s: %s is empty", at, name)
		}
		fields[name] = value
	}
	for _, name := range want {
		if fields[name] == "" {
			return nil, fmt.Errorf("%s: %s is missing", path, name)
		}
	}
	return fields, nil
}

// NodeKeys are a node's id and private keys in its space. They never leave
// the node, except to its own sandboxed workers over their sockets.
type NodeKeys struct {
	ID        netmap.NodeID
	Map       netmap.NodePrivateKey
	WireGuard netmap.WireGuardPrivateKey
}

// String keeps the keys out of logs and error messages.
func (k NodeKeys) String() string   { return "NodeKeys(" + k.ID.String() + ", redacted)" }
func (k NodeKeys) GoString() string { return k.String() }

func parseNodeKeys(path string, data []byte) (NodeKeys, error) {
	f, err := keyFields(path, data, "node-id", "map-key", "wireguard-key")
	if err != nil {
		return NodeKeys{}, err
	}
	var k NodeKeys
	if k.ID, err = netmap.ParseNodeID(f["node-id"]); err != nil {
		return NodeKeys{}, fmt.Errorf("%s: node-id: %w", path, err)
	}
	if k.ID.IsZero() {
		return NodeKeys{}, fmt.Errorf("%s: node-id is zero", path)
	}
	// Parse errors name the field, never the value.
	if k.Map, err = netmap.ParseNodePrivateKey(f["map-key"]); err != nil {
		return NodeKeys{}, fmt.Errorf("%s: map-key: must be 32 hex bytes", path)
	}
	if k.WireGuard, err = netmap.ParseWireGuardPrivateKey(f["wireguard-key"]); err != nil {
		return NodeKeys{}, fmt.Errorf("%s: wireguard-key: must be 32 hex bytes", path)
	}
	return k, nil
}

func parseTrust(path string, data []byte) (netmap.Trust, error) {
	f, err := keyFields(path, data, "space-id", "signing-key", "recovery-key")
	if err != nil {
		return netmap.Trust{}, err
	}
	var t netmap.Trust
	if t.SpaceID, err = netmap.ParseSpaceID(f["space-id"]); err != nil {
		return netmap.Trust{}, fmt.Errorf("%s: space-id: %w", path, err)
	}
	if t.SpaceID.IsZero() {
		return netmap.Trust{}, fmt.Errorf("%s: space-id is zero", path)
	}
	for _, k := range []struct {
		name string
		to   *ed25519.PublicKey
	}{{"signing-key", &t.SigningKey}, {"recovery-key", &t.RecoveryKey}} {
		b, err := hex.DecodeString(f[k.name])
		if err != nil || len(b) != ed25519.PublicKeySize {
			return netmap.Trust{}, fmt.Errorf("%s: %s: must be %d hex bytes", path, k.name, ed25519.PublicKeySize)
		}
		*k.to = b
	}
	return t, nil
}
