package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The state directory (DefaultStateDir) holds exactly what a node needs to
// run (PRD S1) and nothing else:
//
//	node.key   the node's id and private keys in its space (0600)
//	space.pub  the space's id and public keys: what every map is verified against
//	map.bin    the latest map of the space: only the node's own section is readable
//	blobs/     blobs the map names, each in a file named by its SHA-256 (hex)
//
// `thinkpol up` writes no pid, lock or log file there or anywhere else on
// disk (netcfg's locks are on /run, a tmpfs). The one thing it writes is
// blobs/ on a device: the lists its rules use, fetched from peers and
// replaced when the map changes (diskBlobs). A server only reads blobs/,
// its seeds: what it fetches stays in its workers' memory. Every blob is
// checked against the map before use, wherever it was read.
//
// The directory, the key files, the map and the map's directory must be
// owned by the node's user (or root) and writable by nobody else, and are
// never symlinks: whoever could replace space.pub would decide which maps
// the node takes, and whoever could replace map.bin could put back an
// older signed map, which the node takes at its next start (a running node
// refuses anything older than what it has, a starting one has only the
// file).
const (
	NodeKeyFile = "node.key"
	TrustFile   = "space.pub"
	MapFileName = "map.bin"
	BlobDir     = "blobs"
)

// keyFileLimit bounds what is read of a key file.
const keyFileLimit = 4 << 10

// neverOnANode are files a space's admin keeps: a node holding one could
// sign its space's maps.
var neverOnANode = []string{"space.key", "recovery.key"}

// State is what a node runs from: its keys, its space's trust and the
// newest map it has, verified, with the node's section opened.
type State struct {
	Keys  NodeKeys
	Trust netmap.Trust
	Map   *netmap.Map
	// Section is the node's own section of Map.
	Section netmap.Section
	// MapPath is where Map was read from; mapFile is what was read, for
	// noticing a change.
	MapPath string
	mapFile os.FileInfo
	// Unexpected names entries of the state directory that aren't the
	// node's: reported, not used.
	Unexpected []string
	// Removed is set when Map, valid, has no section for the node: it was
	// removed from the space (Section is empty).
	Removed bool
	// OwnMapUnused is set when MapPath is elsewhere but the state
	// directory holds a map.bin too.
	OwnMapUnused bool
}

// LoadState reads and checks a node's state: the keys in dir, the trust in
// dir, and the map at mapPath, which must verify against the trust and
// hold a section for the node's keys, or else says it was removed. It
// changes nothing.
func LoadState(dir, mapPath string) (State, error) {
	var st State
	d, err := openTrustedDir(dir)
	if err != nil {
		return st, fmt.Errorf("state directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	names, err := d.names()
	if err != nil {
		return st, fmt.Errorf("state directory: %w", err)
	}
	for _, name := range names {
		switch {
		case name == NodeKeyFile, name == TrustFile, name == BlobDir:
		case name == MapFileName:
			st.OwnMapUnused = !samePath(filepath.Join(dir, MapFileName), mapPath)
		case slices.Contains(neverOnANode, name):
			return st, fmt.Errorf("%s: a space's private key has no place on a node; remove it and keep it where maps are built", filepath.Join(dir, name))
		default:
			st.Unexpected = append(st.Unexpected, name)
		}
	}

	data, _, err := d.read(NodeKeyFile, true, keyFileLimit)
	if err != nil {
		return st, err
	}
	if st.Keys, err = parseNodeKeys(filepath.Join(dir, NodeKeyFile), data); err != nil {
		return st, err
	}
	if data, _, err = d.read(TrustFile, false, keyFileLimit); err != nil {
		return st, err
	}
	if st.Trust, err = parseTrust(filepath.Join(dir, TrustFile), data); err != nil {
		return st, err
	}

	st.MapPath = mapPath
	envelope, fi, err := readMap(mapPath)
	if err != nil {
		return st, err
	}
	st.mapFile = fi
	if st.Map, err = netmap.Verify(envelope, st.Trust); err != nil {
		return st, fmt.Errorf("%s is not a valid map of space %v: %w", mapPath, st.Trust.SpaceID, err)
	}
	st.Section, err = openSection(st.Map, st.Keys)
	if errors.Is(err, netmap.ErrNotRecipient) {
		// A valid map of the space without the node: it was removed, and
		// waits for a map that includes it again.
		st.Removed = true
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("%s: %w", mapPath, err)
	}
	return st, nil
}

func samePath(a, b string) bool {
	a, errA := filepath.Abs(a)
	b, errB := filepath.Abs(b)
	return errA == nil && errB == nil && a == b
}

// openSection opens the node's section of m and checks it is the node's.
// A map without a section for the node's key is ErrNotRecipient: the node
// was removed from the space.
func openSection(m *netmap.Map, keys NodeKeys) (netmap.Section, error) {
	s, err := m.Open(keys.Map)
	if errors.Is(err, netmap.ErrNotRecipient) {
		return netmap.Section{}, fmt.Errorf("map version %d has no section for this node's key: %w", m.Header().Version, err)
	}
	if err != nil {
		return netmap.Section{}, fmt.Errorf("map version %d: %w", m.Header().Version, err)
	}
	if s.Node.ID != keys.ID {
		return netmap.Section{}, fmt.Errorf("map version %d: the section for this node's key is node %v's, the key file says %v", m.Header().Version, s.Node.ID, keys.ID)
	}
	return s, nil
}

// readMap reads a map file (at most netmap.MaxEnvelopeSize) under the
// state directory's rules: file and directory owned by the node's user or
// root and writable by no one else, no symlink, a regular file (a FIFO is
// refused without blocking).
func readMap(path string) ([]byte, os.FileInfo, error) {
	d, err := openTrustedDir(filepath.Dir(path))
	if err != nil {
		return nil, nil, fmt.Errorf("the map's directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	return d.read(filepath.Base(path), false, netmap.MaxEnvelopeSize)
}

// mapChanged reports whether the file at path is no longer what was read
// as old (replaced, resized or touched). It only decides whether to read:
// readMap checks what is read.
func mapChanged(old os.FileInfo, path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if old == nil {
		return true, nil
	}
	return !os.SameFile(old, fi) || fi.Size() != old.Size() || !fi.ModTime().Equal(old.ModTime()), nil
}
