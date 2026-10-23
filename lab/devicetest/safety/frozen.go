package safety

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// frozen is FROZEN: the sha256 of each of the package's files.
//
//go:embed FROZEN
var frozen []byte

// FrozenSum names this version of the core: the sha256 of FROZEN. A run
// records it, so its evidence says which core restored the Mac.
func FrozenSum() string {
	s := sha256.Sum256(frozen)
	return hex.EncodeToString(s[:])
}
