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
	prepared   = map[string]image{} // by checkout
)

// Prepare builds the lab image (once per Dockerfile version and platform,
// shared by all checkouts) and cross-compiles thinkpol into root/lab/bin for
// the Docker VM's architecture, with the lab's own tools (labdns). It
// returns the image reference.
func Prepare(ctx context.Context, root string) (string, error) {
	img, err := prepare(ctx, root)
	return img.ref, err
}

func prepare(ctx context.Context, root string) (image, error) {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	if img, ok := prepared[root]; ok {
		return img, nil
	}
	t, err := dockerTarget(ctx)
	if err != nil {
		return image{}, err
	}
	img, err := buildImage(ctx, root, t)
	if err != nil {
		return image{}, err
	}
	if _, err := goBuild(ctx, root, t, filepath.Join(root, "lab", "bin", "thinkpol"), "build", "-trimpath", "./cmd/thinkpol"); err != nil {
		return image{}, err
	}
	// labdns: a stand-in for resolvers out in the world.
	if _, err := goBuild(ctx, root, t, filepath.Join(root, "lab", "bin", "labdns"), "build", "-trimpath", "./lab/labdns"); err != nil {
		return image{}, err
	}
	// censord: the lab's censor, run in the router.
	if _, err := goBuild(ctx, root, t, filepath.Join(root, "lab", "bin", "censord"), "build", "-trimpath", "./lab/censord"); err != nil {
		return image{}, err
	}
	prepared[root] = img
	return img, nil
}

// target is the platform lab containers run on.
type target struct {
	goarch, goarm string
	platform      string
}

func dockerTarget(ctx context.Context) (target, error) {
	arch := os.Getenv(GOARCHEnv)
	if arch == "" {
		res, err := docker(ctx, "version", "--format", "{{.Server.Arch}}")
		if err != nil {
			return target{}, fmt.Errorf("lab: is Docker running? %w", err)
		}
		arch = strings.TrimSpace(res.Stdout)
	}
	t := target{goarch: arch, platform: "linux/" + arch}
	if arch == "arm" {
		t.goarm, t.platform = "7", "linux/arm/v7"
	}
	return t, nil
}

func (t target) env() []string {
	env := []string{"GOOS=linux", "GOARCH=" + t.goarch, "CGO_ENABLED=0"}
	if t.goarm != "" {
		env = append(env, "GOARM="+t.goarm)
	}
	return env
}

// buildImage tags the image with a hash of the Dockerfile and the platform,
// so checkouts with the same Dockerfile share it and a changed one gets its
// own.
func buildImage(ctx context.Context, root string, t target) (image, error) {
	dockerfile, err := os.ReadFile(filepath.Join(root, "lab", "Dockerfile"))
	if err != nil {
		return image{}, err
	}
	sum := sha256.Sum256(append(dockerfile, t.platform...))
	img := image{ref: "thinkpol-lab:" + hex.EncodeToString(sum[:6]), platform: t.platform}
	if _, err := docker(ctx, "image", "inspect", "--format", "{{.Id}}", img.ref); err == nil {
		return img, nil
	}
	// The Dockerfile comes on stdin: no build context, nothing from the
	// checkout ends up in the image.
	if _, err := run(ctx, bytes.NewReader(dockerfile), nil, "docker", "build", "-q", "--platform", t.platform, "-t", img.ref, "-"); err != nil {
		return image{}, fmt.Errorf("lab: build image: %w", err)
	}
	return img, nil
}

// One build per output at a time in this process; across processes the
// rename into place keeps every build whole.
var (
	buildLocksMu sync.Mutex
	buildLocks   = map[string]*sync.Mutex{}
)

// goBuild runs go build or go test -c for the lab's platform, without cgo,
// into a temporary file renamed onto out, so a running lab never sees a
// half-written binary. go test -c writes nothing for a package without
// tests; then out is removed and goBuild reports false.
func goBuild(ctx context.Context, root string, t target, out string, args ...string) (bool, error) {
	buildLocksMu.Lock()
	mu, ok := buildLocks[out]
	if !ok {
		mu = &sync.Mutex{}
		buildLocks[out] = mu
	}
	buildLocksMu.Unlock()
	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".*")
	if err != nil {
		return false, err
	}
	_ = tmp.Close()
	// go build refuses to overwrite a file it didn't write; give it the name
	// only.
	if err := os.Remove(tmp.Name()); err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	cmd := append([]string{"-C", root, args[0], "-o", tmp.Name()}, args[1:]...)
	if _, err := run(ctx, nil, t.env(), "go", cmd...); err != nil {
		return false, fmt.Errorf("lab: %w", err)
	}
	if _, err := os.Stat(tmp.Name()); err != nil {
		_ = os.Remove(out) // a package that lost its tests must not run old ones
		return false, nil
	}
	return true, os.Rename(tmp.Name(), out)
}
