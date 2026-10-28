package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// image and the binaries, built once into this process's own directory.
var (
	preparedMu sync.Mutex
	prepared   = map[string]preparedRun{} // by checkout
)

// preparedRun is what a process prepared for its labs of one checkout.
type preparedRun struct {
	img image
	bin *runBinaries
}

// prepare builds the lab image (once per Dockerfile version and platform,
// shared by all checkouts) and cross-compiles thinkpol, with the lab's own
// tools (labdns, censord), into this process's binary directory under
// root/lab/bin for the Docker VM's architecture; RemoveRunBinaries removes
// the directory.
func prepare(ctx context.Context, root string) (preparedRun, error) {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	if p, ok := prepared[root]; ok {
		return p, nil
	}
	t, img, err := prepareImage(ctx, root)
	if err != nil {
		return preparedRun{}, err
	}
	bin, err := newRunBinaries(ctx, root)
	if err != nil {
		return preparedRun{}, err
	}
	if err := buildTools(ctx, root, t, bin.path); err != nil {
		return preparedRun{}, errors.Join(err, bin.remove(context.WithoutCancel(ctx)))
	}
	p := preparedRun{img: img, bin: bin}
	prepared[root] = p
	return p, nil
}

// prepareImage finds the Docker VM's platform and builds the lab image for
// it.
func prepareImage(ctx context.Context, root string) (target, image, error) {
	t, err := dockerTarget(ctx)
	if err != nil {
		return target{}, image{}, err
	}
	img, err := buildImage(ctx, root, t)
	return t, img, err
}

// buildTools cross-compiles thinkpol and the lab's own tools into dir.
func buildTools(ctx context.Context, root string, t target, dir string) error {
	for _, tool := range []struct{ name, pkg string }{
		{"thinkpol", "./cmd/thinkpol"},
		{"labdns", "./lab/labdns"},   // a stand-in for resolvers out in the world
		{"censord", "./lab/censord"}, // the lab's censor, run in the router
	} {
		if _, err := goBuild(ctx, root, t, filepath.Join(dir, tool.name), "build", "-trimpath", tool.pkg); err != nil {
			return err
		}
	}
	return nil
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
	hexSum := hex.EncodeToString(sum[:6])
	img := image{ref: "thinkpol-lab:" + hexSum, platform: t.platform}
	// The check-then-build spans processes (the two phases of make
	// lab-test build in parallel, and other checkouts building the same
	// tag do too): a host-wide lock keeps a cold cache from building the
	// same image twice.
	dir, err := lockDir()
	if err != nil {
		return image{}, err
	}
	unlock, err := waitLock(ctx, "the lab image build", filepath.Join(dir, "image.lock"))
	if err != nil {
		return image{}, err
	}
	defer unlock()
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

// goBuild runs go build or go test -c for the lab's platform, without cgo,
// into a temporary file renamed onto out. go test -c writes nothing for a
// package without tests; then out is removed and goBuild reports false.
// Each output has one builder, so nothing a lab runs is rebuilt under it:
// a process's tools are built once (prepare), a detached lab's into its
// own directory, and a package's tests once per binary directory (goTest).
func goBuild(ctx context.Context, root string, t target, out string, args ...string) (bool, error) {
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
