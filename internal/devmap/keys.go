package devmap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The files of a key directory. A node's files are <name>.key (private:
// only that node gets it) and <name>.pub (what the map builder reads).
const (
	SpaceKeyFile    = "space.key"    // space id, IPv6 network, signing key: private, stays with the map builder
	RecoveryKeyFile = "recovery.key" // recovery key: private, kept offline
	TrustFile       = "space.pub"    // space id, signing and recovery public keys: every node gets it
)

// NodeKeyFile and NodePublicFile name a node's key files.
func NodeKeyFile(name string) string    { return name + ".key" }
func NodePublicFile(name string) string { return name + ".pub" }

// SpaceKeys are what a space is made with: its id, its overlay IPv6
// network and its private keys.
type SpaceKeys struct {
	ID netmap.SpaceID
	// IPv6Network is the space's random ULA /48 (RFC 4193), used unless a
	// spec fixes one.
	IPv6Network netip.Prefix
	Signing     ed25519.PrivateKey
	Recovery    ed25519.PrivateKey
}

// Trust is what nodes verify the space's maps against.
func (k SpaceKeys) Trust() netmap.Trust {
	return netmap.Trust{
		SpaceID:     k.ID,
		SigningKey:  k.Signing.Public().(ed25519.PublicKey),
		RecoveryKey: k.Recovery.Public().(ed25519.PublicKey),
	}
}

// String keeps the keys out of logs and error messages.
func (k SpaceKeys) String() string   { return "SpaceKeys(" + k.ID.String() + ", redacted)" }
func (k SpaceKeys) GoString() string { return k.String() }

// NodeKeys are a node's id and private keys in one space.
type NodeKeys struct {
	// ID is random and opaque, as netmap wants node ids.
	ID        netmap.NodeID
	Map       netmap.NodePrivateKey
	WireGuard netmap.WireGuardPrivateKey
}

// NodePublic is what the map builder knows of a node.
type NodePublic struct {
	ID        netmap.NodeID
	Map       netmap.NodePublicKey
	WireGuard netmap.WireGuardKey
}

// Public returns the public part of k.
func (k NodeKeys) Public() NodePublic {
	return NodePublic{ID: k.ID, Map: k.Map.Public(), WireGuard: k.WireGuard.Public()}
}

// NewSpaceKeys makes a space's id, IPv6 network and keys from random
// (crypto/rand when nil).
func NewSpaceKeys(random io.Reader) (SpaceKeys, error) {
	random = orCryptoRand(random)
	var k SpaceKeys
	var ula [16]byte
	var signing, recovery [ed25519.SeedSize]byte
	ula[0] = 0xfd
	for _, b := range [][]byte{k.ID[:], ula[1:6], signing[:], recovery[:]} {
		if _, err := io.ReadFull(random, b); err != nil {
			return SpaceKeys{}, err
		}
	}
	k.IPv6Network = netip.PrefixFrom(netip.AddrFrom16(ula), 48)
	k.Signing = ed25519.NewKeyFromSeed(signing[:])
	k.Recovery = ed25519.NewKeyFromSeed(recovery[:])
	return k, nil
}

// NewNodeKeys makes a node's id and keys from random (crypto/rand when
// nil).
func NewNodeKeys(random io.Reader) (NodeKeys, error) {
	random = orCryptoRand(random)
	var k NodeKeys
	for k.ID.IsZero() {
		if _, err := io.ReadFull(random, k.ID[:]); err != nil {
			return NodeKeys{}, err
		}
	}
	for _, b := range [][]byte{k.Map[:], k.WireGuard[:]} {
		if _, err := io.ReadFull(random, b); err != nil {
			return NodeKeys{}, err
		}
	}
	k.WireGuard[0] &= 248 // clamped, as `wg genkey` does
	k.WireGuard[31] = k.WireGuard[31]&127 | 64
	return k, nil
}

func orCryptoRand(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// GenerateSpace makes a space and writes space.key and space.pub into dir
// and recovery.key into recoveryDir, all or nothing: no file is replaced,
// and nothing is left behind on failure.
func GenerateSpace(dir, recoveryDir string) (SpaceKeys, error) {
	k, err := NewSpaceKeys(nil)
	if err != nil {
		return SpaceKeys{}, err
	}
	return k, writeKeyFiles(spaceFiles(dir, recoveryDir, k))
}

// GenerateNodes makes keys for the named nodes and writes their files into
// dir, all or nothing: every name is checked first, no file is replaced,
// and nothing is left behind on failure.
func GenerateNodes(dir string, names []string) ([]NodeKeys, error) {
	if len(names) == 0 {
		return nil, errors.New("no node names")
	}
	for i, name := range names {
		if err := CheckName(name); err != nil {
			return nil, err
		}
		if slices.Contains(names[:i], name) {
			return nil, fmt.Errorf("node %s is named twice", name)
		}
	}
	keys := make([]NodeKeys, len(names))
	var files []keyFile
	for i, name := range names {
		k, err := NewNodeKeys(nil)
		if err != nil {
			return nil, err
		}
		keys[i] = k
		files = append(files, nodeFiles(dir, name, k)...)
	}
	return keys, writeKeyFiles(files)
}

// Key files are a few `field: "value"` lines (YAML) under a comment saying
// what they are. Values are quoted so no YAML reader takes a hex string of
// digits for a number; this reader takes them as written either way.

type keyFile struct {
	path    string
	private bool
	comment string
	fields  [][2]string
}

func spaceFiles(dir, recoveryDir string, k SpaceKeys) []keyFile {
	t := k.Trust()
	id := k.ID.String()
	return []keyFile{
		{filepath.Join(dir, SpaceKeyFile), true, "Space signing key: private, keep it where maps are built",
			[][2]string{{"space-id", id}, {"ipv6-network", k.IPv6Network.String()}, {"signing-key", hex.EncodeToString(k.Signing.Seed())}}},
		{filepath.Join(recoveryDir, RecoveryKeyFile), true, "Space recovery key: private, keep it offline",
			[][2]string{{"space-id", id}, {"recovery-key", hex.EncodeToString(k.Recovery.Seed())}}},
		{filepath.Join(dir, TrustFile), false, "Space public keys: every node verifies its maps with them",
			[][2]string{{"space-id", id}, {"signing-key", hex.EncodeToString(t.SigningKey)}, {"recovery-key", hex.EncodeToString(t.RecoveryKey)}}},
	}
}

func nodeFiles(dir, name string, k NodeKeys) []keyFile {
	pub := k.Public()
	return []keyFile{
		{filepath.Join(dir, NodeKeyFile(name)), true, fmt.Sprintf("Keys of node %s: private, only %s gets this file", name, name),
			[][2]string{{"node-id", k.ID.String()}, {"map-key", hex.EncodeToString(k.Map[:])}, {"wireguard-key", hex.EncodeToString(k.WireGuard[:])}}},
		{filepath.Join(dir, NodePublicFile(name)), false, fmt.Sprintf("Id and public keys of node %s, for the map builder", name),
			[][2]string{{"node-id", pub.ID.String()}, {"map-key", pub.Map.String()}, {"wireguard-key", pub.WireGuard.String()}}},
	}
}

func writeKeyFiles(files []keyFile) (err error) {
	for _, f := range files {
		if _, err := os.Lstat(f.path); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s exists; keys are never replaced", f.path)
		}
	}
	var written []string
	defer func() {
		if err != nil {
			for _, p := range written {
				_ = os.Remove(p)
			}
		}
	}()
	dirs := map[string]bool{}
	for _, f := range files {
		dir := filepath.Dir(f.path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		dirs[dir] = true
		var b strings.Builder
		b.WriteString("# thinkpol development keys. " + f.comment + ".\n")
		for _, kv := range f.fields {
			fmt.Fprintf(&b, "%s: %q\n", kv[0], kv[1])
		}
		perm := os.FileMode(0o644)
		if f.private {
			perm = 0o600
		}
		if err := writeNew(f.path, []byte(b.String()), perm); err != nil {
			return err
		}
		written = append(written, f.path)
	}
	for dir := range dirs {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// writeNew creates path with exactly perm, whatever the umask, and makes
// it durable before returning.
func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// syncDir makes a directory's new entries durable. Windows can't sync a
// directory, and doesn't need to.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// WriteMap writes a map to path, replacing the file only once the map is
// fully written and synced, so a node reading it never sees half of one.
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
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

type keyFields map[string]scalar

// readKeyFile reads a key file's fields. A private file others can read is
// refused (the mode can't be checked on Windows).
func readKeyFile(path string, private bool, want ...string) (keyFields, error) {
	if private && runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%s: mode %04o lets others read a private key; chmod 600 it", path, perm)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f keyFields
	if err := yaml.UnmarshalWithOptions(data, &f); err != nil {
		return nil, decodeError(path, err)
	}
	for name, v := range f {
		if !slices.Contains(want, name) {
			return nil, &Error{File: path, Pos: v.pos, Msg: fmt.Sprintf("unknown field %q", name)}
		}
	}
	for _, name := range want {
		if !f[name].set() {
			return nil, &Error{File: path, Msg: name + " is missing"}
		}
	}
	return f, nil
}

// parseField parses one field with a netmap parser, reporting where it is.
func parseField[T any](path string, f keyFields, name string, parse func(string) (T, error)) (T, error) {
	v := f[name]
	t, err := parse(v.text)
	if err != nil {
		return t, &Error{File: path, Pos: v.pos, Msg: fmt.Sprintf("%s: %s", name, strings.TrimPrefix(err.Error(), "netmap: "))}
	}
	return t, nil
}

func parseSeed(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("must be %d hex bytes", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func parseEd25519Public(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("must be %d hex bytes", ed25519.PublicKeySize)
	}
	return b, nil
}

func parseULA(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !netmap.IsOverlayIPv6(p) {
		return netip.Prefix{}, fmt.Errorf("%q is not a ULA /48", s)
	}
	return p, nil
}

// ReadSpaceKeys reads space.key: the space's id, IPv6 network and signing
// key. The recovery key isn't needed to build maps and is left out.
func ReadSpaceKeys(path string) (SpaceKeys, error) {
	f, err := readKeyFile(path, true, "space-id", "ipv6-network", "signing-key")
	if err != nil {
		return SpaceKeys{}, err
	}
	var k SpaceKeys
	if k.ID, err = parseField(path, f, "space-id", netmap.ParseSpaceID); err != nil {
		return SpaceKeys{}, err
	}
	if k.IPv6Network, err = parseField(path, f, "ipv6-network", parseULA); err != nil {
		return SpaceKeys{}, err
	}
	if k.Signing, err = parseField(path, f, "signing-key", parseSeed); err != nil {
		return SpaceKeys{}, err
	}
	return k, nil
}

// ReadTrust reads space.pub.
func ReadTrust(path string) (netmap.Trust, error) {
	f, err := readKeyFile(path, false, "space-id", "signing-key", "recovery-key")
	if err != nil {
		return netmap.Trust{}, err
	}
	var t netmap.Trust
	if t.SpaceID, err = parseField(path, f, "space-id", netmap.ParseSpaceID); err != nil {
		return netmap.Trust{}, err
	}
	if t.SigningKey, err = parseField(path, f, "signing-key", parseEd25519Public); err != nil {
		return netmap.Trust{}, err
	}
	if t.RecoveryKey, err = parseField(path, f, "recovery-key", parseEd25519Public); err != nil {
		return netmap.Trust{}, err
	}
	return t, nil
}

// ReadNodeKey reads a node's id and private keys from <name>.key.
func ReadNodeKey(path string) (NodeKeys, error) {
	f, err := readKeyFile(path, true, "node-id", "map-key", "wireguard-key")
	if err != nil {
		return NodeKeys{}, err
	}
	var k NodeKeys
	if k.ID, err = parseNodeID(path, f); err != nil {
		return NodeKeys{}, err
	}
	if k.Map, err = parseField(path, f, "map-key", netmap.ParseNodePrivateKey); err != nil {
		return NodeKeys{}, err
	}
	if k.WireGuard, err = parseField(path, f, "wireguard-key", netmap.ParseWireGuardPrivateKey); err != nil {
		return NodeKeys{}, err
	}
	return k, nil
}

func parseNodeID(path string, f keyFields) (netmap.NodeID, error) {
	id, err := parseField(path, f, "node-id", netmap.ParseNodeID)
	if err == nil && id.IsZero() {
		err = &Error{File: path, Pos: f["node-id"].pos, Msg: "node-id is zero"}
	}
	return id, err
}

// ReadNodePublic reads a node's id and public keys from <name>.pub.
func ReadNodePublic(path string) (NodePublic, error) {
	f, err := readKeyFile(path, false, "node-id", "map-key", "wireguard-key")
	if err != nil {
		return NodePublic{}, err
	}
	var p NodePublic
	if p.ID, err = parseNodeID(path, f); err != nil {
		return NodePublic{}, err
	}
	if p.Map, err = parseField(path, f, "map-key", netmap.ParseNodePublicKey); err != nil {
		return NodePublic{}, err
	}
	if p.WireGuard, err = parseField(path, f, "wireguard-key", netmap.ParseWireGuardKey); err != nil {
		return NodePublic{}, err
	}
	return p, nil
}

// Keys are what Plan needs besides the spec: the space's id, IPv6 network
// and keys, and every node's public part, by name.
type Keys struct {
	Space       netmap.SpaceID
	IPv6Network netip.Prefix
	// Signing signs the map; RecoveryKey goes into its header.
	Signing     ed25519.PrivateKey
	RecoveryKey ed25519.PublicKey
	Nodes       map[string]NodePublic
}

// Trust is what the map built with k verifies against.
func (k Keys) Trust() netmap.Trust {
	return netmap.Trust{SpaceID: k.Space, SigningKey: k.Signing.Public().(ed25519.PublicKey), RecoveryKey: k.RecoveryKey}
}

// String keeps the signing key out of logs and error messages.
func (k Keys) String() string   { return "Keys(" + k.Space.String() + ", redacted)" }
func (k Keys) GoString() string { return k.String() }

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
	k := Keys{Space: sk.ID, IPv6Network: sk.IPv6Network, Signing: sk.Signing, RecoveryKey: trust.RecoveryKey, Nodes: map[string]NodePublic{}}
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

// ReadNames reads the ids in every <name>.pub in dir. Files that aren't
// node public files are skipped.
func ReadNames(dir string) (Names, error) {
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
		if pub, err := ReadNodePublic(p); err == nil {
			names[pub.ID] = name
		}
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
