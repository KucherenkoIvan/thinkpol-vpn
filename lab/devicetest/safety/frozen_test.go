package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheSafetyCoreIsFrozen pins every file of the package (doc.go
// "Frozen"): a change to the core is a ticket of its own, with the
// owner's approval.
func TestTheSafetyCoreIsFrozen(t *testing.T) {
	want, err := os.ReadFile("FROZEN")
	if err != nil {
		t.Fatal(err)
	}
	if got := frozenList(t); got != string(want) {
		t.Fatalf("lab/devicetest/safety differs from its pin. Changing the safety core needs a ticket of its own and "+
			"the owner's approval (doc.go, \"Frozen\"). With both, FROZEN becomes:\n%s", got)
	}
}

// frozenList is FROZEN's content for the files as they are: one
// "<sha256>  <path>" line a file, sorted, FROZEN itself left out.
func frozenList(t *testing.T) string {
	var b strings.Builder
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == "FROZEN" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + filepath.ToSlash(path) + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
