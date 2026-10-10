package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProjectPrefix starts every lab's Compose project name. Nothing can remove
// it, and the harness never tears down a project without it: projects that
// aren't the lab's are out of reach.
const ProjectPrefix = "tplab-"

// ProjectEnv overrides the checkout's part of the project name, e.g. to run
// two labs from one checkout at once. It is validated, and ProjectPrefix is
// still prepended.
const ProjectEnv = "THINKPOL_LAB_PROJECT"

// overridePattern is what ProjectEnv may hold.
var overridePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

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
// checkout at root: ProjectPrefix, then the checkout directory's name (a
// worktree is named after its branch) and a hash of its path, so two
// checkouts never share a name; or ProjectPrefix and ProjectEnv.
func CheckoutProject(root string) (string, error) {
	if v := os.Getenv(ProjectEnv); v != "" {
		if !overridePattern.MatchString(v) {
			return "", fmt.Errorf("lab: %s=%q: want %s", ProjectEnv, v, overridePattern)
		}
		return ProjectPrefix + v, nil
	}
	name := slug(filepath.Base(root), 32)
	if name == "" {
		name = "checkout"
	}
	return ProjectPrefix + name + "-" + shortHash(root), nil
}

// testProject is the Compose project of one test's lab. The package
// directory is hashed in because packages are tested in parallel and may
// share test names.
func testProject(checkout, pkgDir, testName string) string {
	return checkout + "-t-" + slug(testName, 24) + "-" + shortHash(pkgDir+"\x00"+testName)
}

// GoTestProject is the Compose project prefix of the labs that run packages'
// tests in a node (labctl gotest).
func GoTestProject(checkout string) string { return checkout + "-gotest" }

// belongsTo reports whether a Compose project was started from the checkout
// whose prefix is checkout.
func belongsTo(project, checkout string) bool {
	return project == checkout || strings.HasPrefix(project, checkout+"-")
}

// startedByTests reports whether a checkout's project is one that tests or
// labctl gotest started, as opposed to make lab-up's.
func startedByTests(project, checkout string) bool {
	return strings.HasPrefix(project, checkout+"-t-") || belongsTo(project, GoTestProject(checkout))
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
