package blobs

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var (
	// ErrMismatch is a blob whose size or SHA-256 isn't its reference's:
	// whoever produced it, it is not the blob the map names.
	ErrMismatch = errors.New("blobs: content does not match the map's reference")
	// ErrUndecodable is a blob that matches its reference but is no valid
	// blob of its kind: the map names a bad blob, so no peer can do better.
	ErrUndecodable = errors.New("blobs: the map's blob is not a valid blob of its kind")
)

// Check reports whether data is the blob ref names: ref's size and SHA-256
// (over the bytes as they are, uncompressed), and for a GeoIP list a
// canonical list (lists.Decode). Blobs of kinds this node doesn't know are
// checked by hash alone: it holds and passes them on without reading them.
func Check(ref netmap.BlobRef, data []byte) error {
	if uint64(len(data)) != ref.Size || sha256.Sum256(data) != ref.SHA256 {
		return ErrMismatch
	}
	if ref.Kind == netmap.BlobGeoIP {
		if _, err := lists.Decode(data); err != nil {
			return fmt.Errorf("%w: %w", ErrUndecodable, err)
		}
	}
	return nil
}
