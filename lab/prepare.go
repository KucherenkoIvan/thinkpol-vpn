package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// GOARCHEnv overrides the architecture binaries are built for; by default
// it is the Docker server's.
const GOARCHEnv = "THINKPOL_LAB_GOARCH"

// prepared caches, per checkout, what every lab of this process shares: the
// image and the binaries, built once.
var (
	preparedMu sync.Mutex
	prepared   = map[string]string{} // root → image
)

// Prepare builds the lab image (once per Dockerfile version, shared by all
// checkouts) and cross-compiles thinkpol into root/lab/bin for the Docker
// VM's architecture. It returns the image reference.
func Prepare(ctx context.Context, root string) (string, error) {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	if image, ok := prepared[root]; ok {
		return image, nil
	}
	image, err := buildImage(ctx, root)
	if err != nil {
		return "", err
	}
	arch, err := dockerArch(ctx)
	if err != nil {
		return "", err
	}
	if err := buildBinary(ctx, root, arch, "./cmd/thinkpol", filepath.Join(root, "lab", "bin", "thinkpol")); err != nil {
		return "", err
	}
	prepared[root] = image
	return image, nil
}

// buildImage tags the image with a hash of the Dockerfile, so checkouts with
// the same Dockerfile share it and a changed one gets its own.
func buildImage(ctx context.Context, root string) (string, error) {
	dockerfile, err := os.ReadFile(filepath.Join(root, "lab", "Dockerfile"))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(dockerfile)
	image := "thinkpol-lab:" + hex.EncodeToString(sum[:6])
	if _, err := docker(ctx, "image", "inspect", "--format", "{{.Id}}", image); err == nil {
		return image, nil
	}
	// The Dockerfile comes on stdin: no build context, nothing from the
	// checkout ends up in the image.
	if _, err := run(ctx, bytes.NewReader(dockerfile), nil, "docker", "build", "-q", "-t", image, "-"); err != nil {
		return "", fmt.Errorf("lab: build image: %w", err)
	}
	return image, nil
}

func dockerArch(ctx context.Context) (string, error) {
	if arch := os.Getenv(GOARCHEnv); arch != "" {
		return arch, nil
	}
	res, err := docker(ctx, "version", "--format", "{{.Server.Arch}}")
	if err != nil {
		return "", fmt.Errorf("lab: is Docker running? %w", err)
	}
	return strings.TrimSpace(res.Stdout), nil
}

// buildBinary cross-compiles a main package for the lab, without cgo, and
// renames it into place so a running lab never sees a half-written file.
func buildBinary(ctx context.Context, root, arch, pkg, out string) error {
	return goBuild(ctx, root, arch, out, "build", "-trimpath", pkg)
}

// buildTestBinary compiles a package's tests for the lab. It reports false
// when the package has no tests.
func buildTestBinary(ctx context.Context, root, arch, pkg, out string) (bool, error) {
	if err := goBuild(ctx, root, arch, out, "test", "-c", pkg); err != nil {
		return false, err
	}
	_, err := os.Stat(out)
	return err == nil, nil
}

func goBuild(ctx context.Context, root, arch, out string, args ...string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	tmp := out + ".tmp-" + shortHash(fmt.Sprint(os.Getpid(), args))
	args = append(args[:1:1], append([]string{"-o", tmp}, args[1:]...)...)
	env := []string{"GOOS=linux", "GOARCH=" + arch, "CGO_ENABLED=0"}
	cmd := append([]string{"-C", root}, args...)
	if _, err := run(ctx, nil, env, "go", cmd...); err != nil {
		return fmt.Errorf("lab: %w", err)
	}
	if _, err := os.Stat(tmp); err != nil {
		return nil // go test -c writes nothing for a package without tests
	}
	return os.Rename(tmp, out)
}
