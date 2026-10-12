package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// blobFileName is a blob's file in the state directory's BlobDir: the hex
// SHA-256 of its content.
func blobFileName(sha [32]byte) string { return hex.EncodeToString(sha[:]) }

func isBlobFileName(name string) bool {
	b, err := hex.DecodeString(name)
	return err == nil && len(b) == sha256.Size && name == strings.ToLower(name)
}

// blobIndexFile, in BlobDir, names the stored blobs: one line per blob,
// "<kind> <name> <hex sha256> <size>", as named when stored. It is where
// the previous version of a list comes from after a restart.
const blobIndexFile = "index"

// blobIndexLimit bounds what is read of the index.
const blobIndexLimit = 64 << 10

// diskBlobs keeps a device's blobs in its state directory's BlobDir
// (blobs.Store): the lists its rules use must be there from the moment it
// starts, before any peer is reachable. What it reads is checked against
// the map before use, so a file there can't make the node use anything
// the map doesn't name. The directory is made with the first blob and
// removed with the last.
type diskBlobs struct {
	dir string // the state directory
	log *slog.Logger
}

func (d diskBlobs) Load(ref netmap.BlobRef) []byte {
	data, err := readBlob(d.dir, ref)
	if err != nil {
		d.log.Warn("reading a stored blob", "err", err)
	}
	return data
}

// readBlob reads ref's file from the state directory's BlobDir: nil, nil
// when there is none.
func readBlob(stateDir string, ref netmap.BlobRef) ([]byte, error) {
	bd, err := openTrustedDir(filepath.Join(stateDir, BlobDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = bd.Close() }()
	data, _, err := bd.read(blobFileName(ref.SHA256), false, int64(min(ref.Size, blobs.MaxBlobSize)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (d diskBlobs) Save(ref netmap.BlobRef, data []byte) error {
	sd, err := openTrustedDir(d.dir)
	if err != nil {
		return err
	}
	err = sd.mkdir(BlobDir)
	_ = sd.Close()
	if err != nil {
		return err
	}
	bd, err := openTrustedDir(filepath.Join(d.dir, BlobDir))
	if err != nil {
		return err
	}
	defer func() { _ = bd.Close() }()
	if err := bd.write(blobFileName(ref.SHA256), data, 0o600); err != nil {
		return err
	}
	index := slices.DeleteFunc(readBlobIndex(bd), func(r netmap.BlobRef) bool {
		return r.SHA256 == ref.SHA256 || r.Kind == ref.Kind && r.Name == ref.Name && !d.has(bd, r)
	})
	return bd.write(blobIndexFile, encodeBlobIndex(append(index, ref)), 0o600)
}

func (d diskBlobs) has(bd *trustedDir, ref netmap.BlobRef) bool {
	_, _, err := bd.read(blobFileName(ref.SHA256), false, int64(min(ref.Size, blobs.MaxBlobSize)))
	return err == nil
}

func (d diskBlobs) Index() []netmap.BlobRef {
	bd, err := openTrustedDir(filepath.Join(d.dir, BlobDir))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.log.Warn("reading the stored blobs' index", "err", err)
		}
		return nil
	}
	defer func() { _ = bd.Close() }()
	return readBlobIndex(bd)
}

// readBlobIndex reads BlobDir's index; lines it can't read are skipped:
// whatever it names is checked against the map before use anyway.
func readBlobIndex(bd *trustedDir) []netmap.BlobRef {
	data, _, err := bd.read(blobIndexFile, false, blobIndexLimit)
	if err != nil {
		return nil
	}
	var out []netmap.BlobRef
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 4 {
			continue
		}
		kind, err1 := strconv.ParseUint(f[0], 10, 8)
		sum, err2 := hex.DecodeString(f[2])
		size, err3 := strconv.ParseUint(f[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || len(sum) != sha256.Size || lists.CheckName(f[1]) != nil || size == 0 {
			continue
		}
		out = append(out, netmap.BlobRef{Kind: netmap.BlobKind(kind), Name: f[1], SHA256: [32]byte(sum), Size: size})
	}
	return out
}

func encodeBlobIndex(refs []netmap.BlobRef) []byte {
	var b strings.Builder
	for _, r := range refs {
		if lists.CheckName(r.Name) != nil {
			continue // a name the index can't hold stands in for nothing
		}
		fmt.Fprintf(&b, "%d %s %s %d\n", r.Kind, r.Name, blobFileName(r.SHA256), r.Size)
	}
	return []byte(b.String())
}

func (d diskBlobs) Prune(keep []netmap.BlobRef) error {
	bd, err := openTrustedDir(filepath.Join(d.dir, BlobDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := bd.names()
	if err != nil {
		_ = bd.Close()
		return err
	}
	kept := map[string]bool{}
	for _, ref := range keep {
		kept[blobFileName(ref.SHA256)] = true
	}
	var errs []error
	left := 0
	for _, name := range names {
		ours := isBlobFileName(name) || name == blobIndexFile || strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".new")
		if kept[name] || !ours {
			left++
			continue
		}
		if err := bd.remove(name, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			left++
		}
	}
	if len(keep) > 0 {
		if err := bd.write(blobIndexFile, encodeBlobIndex(keep), 0o600); err != nil {
			errs = append(errs, err)
		}
		left++
	}
	_ = bd.Close()
	if left == 0 {
		if sd, err := openTrustedDir(d.dir); err == nil {
			_ = sd.remove(BlobDir, true)
			_ = sd.Close()
		}
	}
	return errors.Join(errs...)
}

// seedBlobs reads the blobs of header a server's state directory holds,
// put there by whoever provisions the node: checked against the map, and
// within the limits a worker holds. A server keeps no blob it fetched on
// disk (DESIGN "Node safety"); these are its seeds, read and never written.
func seedBlobs(stateDir string, header []netmap.BlobRef, log *slog.Logger) [][]byte {
	var out [][]byte
	var total uint64
	for _, ref := range header {
		if ref.Size > blobs.MaxBlobSize || total+ref.Size > blobs.ServerMaxHeldSize {
			continue
		}
		data, err := readBlob(stateDir, ref)
		switch {
		case err != nil:
			log.Warn("reading a seeded blob", "err", err)
			continue
		case data == nil:
			continue
		}
		if err := blobs.Check(ref, data); err != nil {
			log.Warn("a seeded blob doesn't match the map; not used", "file", filepath.Join(stateDir, BlobDir, blobFileName(ref.SHA256)), "err", err)
			continue
		}
		out = append(out, data)
		total += ref.Size
	}
	return out
}

// seedStore is a worker's blobs.Store: the seeds its supervisor sent
// (worker.Seeds), in memory; a worker keeps nothing on disk.
type seedStore struct{ seeds *worker.Seeds }

func (s seedStore) Load(ref netmap.BlobRef) []byte { return s.seeds.Get(ref.SHA256) }

func (s seedStore) Save(netmap.BlobRef, []byte) error { return nil }

// Prune leaves the seeds alone: the worker drops those a new map doesn't
// name when the map arrives (retainSeeds).
func (s seedStore) Prune([]netmap.BlobRef) error { return nil }

// Index is empty: a server needs no stand-ins, it uses no list itself.
func (s seedStore) Index() []netmap.BlobRef { return nil }
