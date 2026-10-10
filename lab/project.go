package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ProjectEnv overrides the checkout's project prefix, e.g. to run two labs
// from one checkout at once.
const ProjectEnv = "THINKPOL_LAB_PROJECT"

// Root finds the checkout: the nearest directory at or above the working
// directory that holds go.mod.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("lab: no go.mod at or above the working directory")
		}
		dir = parent
	}
}

// CheckoutProject is the prefix of every Compose project started from the
// checkout at root: the checkout directory's name (a worktree is named after
// its branch) and a hash of its path, so two checkouts never share a name.
func CheckoutProject(root string) string {
	if p := slug(os.Getenv(ProjectEnv), 48); p != "" {
		return p
	}
	return slug(filepath.Base(root), 32) + "-" + shortHash(root)
}

// testProject is the Compose project of one test's lab. The package
// directory is hashed in because packages are tested in parallel and may
// share test names.
func testProject(checkout, pkgDir, testName string) string {
	return checkout + "-t-" + slug(testName, 24) + "-" + shortHash(pkgDir+"\x00"+testName)
}

// belongsTo reports whether a Compose project was started from the checkout
// whose prefix is checkout.
func belongsTo(project, checkout string) bool {
	return project == checkout || strings.HasPrefix(project, checkout+"-")
}

// slug lowercases s and keeps [a-z0-9-], as Compose project names require.
func slug(s string, maxLen int) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		switch {
		case ok:
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= maxLen {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:3])
}
