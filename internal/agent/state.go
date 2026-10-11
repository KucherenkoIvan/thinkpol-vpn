package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The state directory (DefaultStateDir) holds exactly what a node needs to
// run (PRD S1) and nothing else:
//
//	node.key   the node's id and private keys in its space (0600)
//	space.pub  the space's id and public keys: what every map is verified against
//	map.bin    the latest map of the space: only the node's own section is readable
//
// `thinkpol up` only reads it: it writes no pid, lock or log file there or
// anywhere else on disk (netcfg's locks are on /run, a tmpfs).
const (
	NodeKeyFile = "node.key"
	TrustFile   = "space.pub"
	MapFile     = "map.bin"
)

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
}

// LoadState reads and checks a node's state: the keys in dir, the trust in
// dir, and the map at mapPath, which must verify against the trust and
// hold a section for the node's keys. It changes nothing.
func LoadState(dir, mapPath string) (State, error) {
	var st State
	entries, err := os.ReadDir(dir)
	if err != nil {
		return st, fmt.Errorf("state directory: %w", err)
	}
	if err := notWritableByOthers(dir); err != nil {
		return st, err
	}
	for _, e := range entries {
		switch name := e.Name(); {
		case name == NodeKeyFile, name == TrustFile, name == MapFile:
		case slices.Contains(neverOnANode, name):
			return st, fmt.Errorf("%s: a space's private key has no place on a node; remove it and keep it where maps are built", filepath.Join(dir, name))
		default:
			st.Unexpected = append(st.Unexpected, name)
		}
	}

	keyPath := filepath.Join(dir, NodeKeyFile)
	data, err := readPrivate(keyPath)
	if err != nil {
		return st, err
	}
	if st.Keys, err = parseNodeKeys(keyPath, data); err != nil {
		return st, err
	}
	trustPath := filepath.Join(dir, TrustFile)
	if err := notWritableByOthers(trustPath); err != nil {
		return st, err
	}
	if data, err = os.ReadFile(trustPath); err != nil {
		return st, err
	}
	if st.Trust, err = parseTrust(trustPath, data); err != nil {
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
	if st.Section, err = openSection(st.Map, st.Keys); err != nil {
		return st, fmt.Errorf("%s: %w", mapPath, err)
	}
	return st, nil
}

// openSection opens the node's section of m and checks it is the node's.
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

// readMap reads a map file, at most netmap.MaxEnvelopeSize of it.
func readMap(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, netmap.MaxEnvelopeSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > netmap.MaxEnvelopeSize {
		return nil, nil, fmt.Errorf("%s: larger than a map can be (%d bytes)", path, netmap.MaxEnvelopeSize)
	}
	return b, fi, nil
}

// readPrivate reads a file only the node may read (its mode isn't checked
// on Windows).
func readPrivate(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%s: mode %04o lets others read the node's private keys; chmod 600 it", path, perm)
		}
	}
	return os.ReadFile(path)
}

// notWritableByOthers refuses a state directory or trust file others could
// change: whoever can replace space.pub decides which maps the node takes.
func notWritableByOthers(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s: mode %04o lets others change it; chmod go-w it", path, perm)
	}
	return nil
}

// mapChanged reports whether the file at path is no longer what was read
// as old (replaced, resized or touched).
func mapChanged(old os.FileInfo, path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if old == nil {
		return true, nil
	}
	return !os.SameFile(old, fi) || fi.Size() != old.Size() || !fi.ModTime().Equal(old.ModTime()), nil
}
