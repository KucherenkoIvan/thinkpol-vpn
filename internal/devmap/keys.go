package devmap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/curve25519"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The files of a key directory. A node's files are <name>.key (private:
// only that node gets it) and <name>.pub (what the map builder reads).
const (
	SpaceKeyFile    = "space.key"    // space id and signing key: private, stays with the map builder
	RecoveryKeyFile = "recovery.key" // recovery key: private, kept offline
	TrustFile       = "space.pub"    // space id, signing and recovery public keys: every node gets it
)

// NodeKeyFile and NodePublicFile name a node's key files.
func NodeKeyFile(name string) string    { return name + ".key" }
func NodePublicFile(name string) string { return name + ".pub" }

// SpaceKeys are a space's id and private keys.
type SpaceKeys struct {
	ID       netmap.SpaceID
	Signing  ed25519.PrivateKey
	Recovery ed25519.PrivateKey
}

// Trust is what nodes verify the space's maps against.
func (k SpaceKeys) Trust() netmap.Trust {
	return netmap.Trust{
		SpaceID:     k.ID,
		SigningKey:  k.Signing.Public().(ed25519.PublicKey),
		RecoveryKey: k.Recovery.Public().(ed25519.PublicKey),
	}
}

// NodeKey is a node's private keys in one space: the key its map section is
// sealed to, and its WireGuard key.
type NodeKey struct {
	Map       netmap.NodePrivateKey
	WireGuard WireGuardPrivateKey
}

// NodePublic is the public half of a NodeKey.
type NodePublic struct {
	Map       netmap.NodePublicKey
	WireGuard netmap.WireGuardKey
}

// Public returns the public halves of k.
func (k NodeKey) Public() NodePublic {
	return NodePublic{Map: k.Map.Public(), WireGuard: k.WireGuard.Public()}
}

// WireGuardPrivateKey is a node's WireGuard (Curve25519) private key,
// clamped as `wg genkey` does.
type WireGuardPrivateKey [32]byte

// Public returns the WireGuard public key of k.
func (k WireGuardPrivateKey) Public() netmap.WireGuardKey {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("devmap: deriving a WireGuard public key: %v", err)) // never with the base point
	}
	return netmap.WireGuardKey(pub)
}

// String keeps the key out of logs and error messages.
func (WireGuardPrivateKey) String() string { return "WireGuardPrivateKey(redacted)" }

// GoString keeps the key out of %#v.
func (k WireGuardPrivateKey) GoString() string { return k.String() }

// NewSpaceKeys makes a space id and its signing and recovery keys from
// random (crypto/rand when nil).
func NewSpaceKeys(random io.Reader) (SpaceKeys, error) {
	random = orCryptoRand(random)
	var k SpaceKeys
	var signing, recovery [ed25519.SeedSize]byte
	for _, b := range [][]byte{k.ID[:], signing[:], recovery[:]} {
		if _, err := io.ReadFull(random, b); err != nil {
			return SpaceKeys{}, err
		}
	}
	k.Signing = ed25519.NewKeyFromSeed(signing[:])
	k.Recovery = ed25519.NewKeyFromSeed(recovery[:])
	return k, nil
}

// NewNodeKey makes a node's keys from random (crypto/rand when nil).
func NewNodeKey(random io.Reader) (NodeKey, error) {
	random = orCryptoRand(random)
	var k NodeKey
	for _, b := range [][]byte{k.Map[:], k.WireGuard[:]} {
		if _, err := io.ReadFull(random, b); err != nil {
			return NodeKey{}, err
		}
	}
	k.WireGuard[0] &= 248
	k.WireGuard[31] = k.WireGuard[31]&127 | 64
	return k, nil
}

func orCryptoRand(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// NodeID is a node's id in a space: derived from the space id and the
// node's map key, so it stays the same across builds while the keys do,
// and tells nothing to anyone without the node's public map key (which is
// never in a map).
func NodeID(space netmap.SpaceID, key netmap.NodePublicKey) netmap.NodeID {
	h := sha256.New()
	h.Write([]byte("thinkpol-vpn dev node id\x00"))
	h.Write(space[:])
	h.Write(key[:])
	return netmap.NodeID(h.Sum(nil)[:8])
}

// DefaultIPv6Network is the ULA /48 of a space whose spec doesn't fix one:
// RFC 4193's random global id, taken from the (random) space id so it stays
// the same across builds.
func DefaultIPv6Network(space netmap.SpaceID) netip.Prefix {
	h := sha256.Sum256(append([]byte("thinkpol-vpn dev ula\x00"), space[:]...))
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:6], h[:5])
	return netip.PrefixFrom(netip.AddrFrom16(a), 48)
}

// Key files are a few `field: "hex"` lines (YAML) under a comment saying
// what they are. Values are quoted so no YAML reader takes a hex string of
// digits for a number; this reader takes them as written either way.

type spaceKeyFile struct {
	SpaceID    scalar `yaml:"space-id"`
	SigningKey scalar `yaml:"signing-key"`
}

type trustFile struct {
	SpaceID     scalar `yaml:"space-id"`
	SigningKey  scalar `yaml:"signing-key"`
	RecoveryKey scalar `yaml:"recovery-key"`
}

type nodeKeyFile struct {
	MapKey       scalar `yaml:"map-key"`
	WireGuardKey scalar `yaml:"wireguard-key"`
}

// WriteSpaceKeys writes the space's three files into dir, refusing to
// replace any existing one.
func WriteSpaceKeys(dir string, k SpaceKeys) error {
	t := k.Trust()
	id := k.ID.String()
	return writeKeyFiles(dir, []keyFile{
		{SpaceKeyFile, true, "Space signing key: private, keep it where maps are built",
			[][2]string{{"space-id", id}, {"signing-key", hex.EncodeToString(k.Signing.Seed())}}},
		{RecoveryKeyFile, true, "Space recovery key: private, keep it offline",
			[][2]string{{"space-id", id}, {"recovery-key", hex.EncodeToString(k.Recovery.Seed())}}},
		{TrustFile, false, "Space public keys: every node verifies its maps with them",
			[][2]string{{"space-id", id}, {"signing-key", hex.EncodeToString(t.SigningKey)}, {"recovery-key", hex.EncodeToString(t.RecoveryKey)}}},
	})
}

// WriteNodeKey writes a node's two files into dir, refusing to replace
// existing ones.
func WriteNodeKey(dir, name string, k NodeKey) error {
	if err := CheckName(name); err != nil {
		return err
	}
	pub := k.Public()
	return writeKeyFiles(dir, []keyFile{
		{NodeKeyFile(name), true, fmt.Sprintf("Keys of node %s: private, only %s gets this file", name, name),
			[][2]string{{"map-key", hex.EncodeToString(k.Map[:])}, {"wireguard-key", hex.EncodeToString(k.WireGuard[:])}}},
		{NodePublicFile(name), false, fmt.Sprintf("Public keys of node %s, for the map builder", name),
			[][2]string{{"map-key", pub.Map.String()}, {"wireguard-key", pub.WireGuard.String()}}},
	})
}

type keyFile struct {
	name    string
	private bool
	comment string
	fields  [][2]string
}

func writeKeyFiles(dir string, files []keyFile) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		if _, err := os.Lstat(filepath.Join(dir, f.name)); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s exists; keys are never replaced", filepath.Join(dir, f.name))
		}
	}
	for _, f := range files {
		var b strings.Builder
		b.WriteString("# thinkpol development keys. " + f.comment + ".\n")
		for _, kv := range f.fields {
			fmt.Fprintf(&b, "%s: %q\n", kv[0], kv[1])
		}
		perm := os.FileMode(0o644)
		if f.private {
			perm = 0o600
		}
		if err := writeNew(filepath.Join(dir, f.name), []byte(b.String()), perm); err != nil {
			return err
		}
	}
	return nil
}

// WriteMap writes a map to path, replacing the file only once the map is
// fully written, so a node reading it never sees half of one.
func WriteMap(path string, envelope []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(envelope)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func readKeyFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.UnmarshalWithOptions(data, v, yaml.Strict()); err != nil {
		return decodeError(path, err)
	}
	return nil
}

func decodeHex(path, field string, v scalar, size int) ([]byte, error) {
	b, err := hex.DecodeString(v.text)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%s: %s must be %d hex bytes", path, field, size)
	}
	return b, nil
}

// ReadSpaceKeys reads a space's id and signing key from space.key; the
// recovery key isn't needed to build maps and is left out.
func ReadSpaceKeys(path string) (SpaceKeys, error) {
	var f spaceKeyFile
	if err := readKeyFile(path, &f); err != nil {
		return SpaceKeys{}, err
	}
	id, err := decodeHex(path, "space-id", f.SpaceID, len(netmap.SpaceID{}))
	if err != nil {
		return SpaceKeys{}, err
	}
	seed, err := decodeHex(path, "signing-key", f.SigningKey, ed25519.SeedSize)
	if err != nil {
		return SpaceKeys{}, err
	}
	return SpaceKeys{ID: netmap.SpaceID(id), Signing: ed25519.NewKeyFromSeed(seed)}, nil
}

// ReadTrust reads space.pub.
func ReadTrust(path string) (netmap.Trust, error) {
	var f trustFile
	if err := readKeyFile(path, &f); err != nil {
		return netmap.Trust{}, err
	}
	id, err := decodeHex(path, "space-id", f.SpaceID, len(netmap.SpaceID{}))
	if err != nil {
		return netmap.Trust{}, err
	}
	signing, err := decodeHex(path, "signing-key", f.SigningKey, ed25519.PublicKeySize)
	if err != nil {
		return netmap.Trust{}, err
	}
	recovery, err := decodeHex(path, "recovery-key", f.RecoveryKey, ed25519.PublicKeySize)
	if err != nil {
		return netmap.Trust{}, err
	}
	return netmap.Trust{SpaceID: netmap.SpaceID(id), SigningKey: signing, RecoveryKey: recovery}, nil
}

// ReadNodeKey reads a node's private keys from <name>.key.
func ReadNodeKey(path string) (NodeKey, error) {
	var f nodeKeyFile
	if err := readKeyFile(path, &f); err != nil {
		return NodeKey{}, err
	}
	m, err := decodeHex(path, "map-key", f.MapKey, 32)
	if err != nil {
		return NodeKey{}, err
	}
	wg, err := decodeHex(path, "wireguard-key", f.WireGuardKey, 32)
	if err != nil {
		return NodeKey{}, err
	}
	return NodeKey{Map: netmap.NodePrivateKey(m), WireGuard: WireGuardPrivateKey(wg)}, nil
}

// ReadNodePublic reads a node's public keys from <name>.pub.
func ReadNodePublic(path string) (NodePublic, error) {
	var f nodeKeyFile
	if err := readKeyFile(path, &f); err != nil {
		return NodePublic{}, err
	}
	m, err := decodeHex(path, "map-key", f.MapKey, 32)
	if err != nil {
		return NodePublic{}, err
	}
	if err := netmap.NodePublicKey(m).Check(); err != nil {
		return NodePublic{}, fmt.Errorf("%s: %v", path, err)
	}
	wg, err := decodeHex(path, "wireguard-key", f.WireGuardKey, 32)
	if err != nil {
		return NodePublic{}, err
	}
	return NodePublic{Map: netmap.NodePublicKey(m), WireGuard: netmap.WireGuardKey(wg)}, nil
}

// Keys are what Plan needs besides the spec: the space's id and keys and
// every node's public keys, by name.
type Keys struct {
	Space netmap.SpaceID
	// Signing signs the map; RecoveryKey goes into its header.
	Signing     ed25519.PrivateKey
	RecoveryKey ed25519.PublicKey
	Nodes       map[string]NodePublic
}

// LoadKeys reads a key directory for a spec: space.key, space.pub, and
// <name>.pub for every node. A missing node file is reported at the node
// in the spec.
func LoadKeys(dir string, s *Spec) (Keys, error) {
	sk, err := ReadSpaceKeys(filepath.Join(dir, SpaceKeyFile))
	if err != nil {
		return Keys{}, err
	}
	trust, err := ReadTrust(filepath.Join(dir, TrustFile))
	if err != nil {
		return Keys{}, err
	}
	if trust.SpaceID != sk.ID || !bytes.Equal(trust.SigningKey, sk.Signing.Public().(ed25519.PublicKey)) {
		return Keys{}, fmt.Errorf("%s and %s are not of the same space", filepath.Join(dir, SpaceKeyFile), filepath.Join(dir, TrustFile))
	}
	k := Keys{Space: sk.ID, Signing: sk.Signing, RecoveryKey: trust.RecoveryKey, Nodes: map[string]NodePublic{}}
	var errs []error
	for _, n := range s.Nodes {
		path := filepath.Join(dir, NodePublicFile(n.Name))
		pub, err := ReadNodePublic(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			errs = append(errs, &Error{File: s.File, Pos: n.Pos, Msg: fmt.Sprintf("%s: no keys in %s (make them with `thinkpol dev keygen node -out %s %s`)", n.Name, path, dir, n.Name)})
		case err != nil:
			errs = append(errs, &Error{File: s.File, Pos: n.Pos, Msg: fmt.Sprintf("%s: %v", n.Name, err)})
		default:
			k.Nodes[n.Name] = pub
		}
	}
	return k, errors.Join(errs...)
}

// Names maps node ids to the names of their key files, for inspect.
type Names map[netmap.NodeID]string

// ReadNames reads every <name>.pub in dir and names the ids those keys have
// in space. Files that aren't node keys are skipped.
func ReadNames(dir string, space netmap.SpaceID) (Names, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	names := Names{}
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), ".pub")
		if CheckName(name) != nil {
			continue
		}
		pub, err := ReadNodePublic(p)
		if err != nil {
			continue
		}
		names[NodeID(space, pub.Map)] = name
	}
	return names, nil
}

// Of is id with its name when known: "0123456789abcdef (device-a)".
func (n Names) Of(id netmap.NodeID) string {
	if name, ok := n[id]; ok {
		return id.String() + " (" + name + ")"
	}
	return id.String()
}
