package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// WGTimerScaleEnv sets the factor the lab's thinkpol binary divides
// WireGuard's timers by; 1 runs the real timers.
const WGTimerScaleEnv = "THINKPOL_LAB_WG_TIMER_SCALE"

// DefaultWGTimerScale is the factor without WGTimerScaleEnv.
const DefaultWGTimerScale = 10

// maxWGTimerScale keeps the rhythm cells' traffic in the same order
// against the scaled timers as at real time: their hold pings every 0.4
// KEEPALIVE_TIMEOUT (scaled), which must stay above wireguard-rhythm's
// 300 ms count settle, a real-time choice; past 13 it doesn't.
const maxWGTimerScale = 10

// WGTimerScale is the factor WireGuard's timers run sped up by in the lab:
// WGTimerScaleEnv, or DefaultWGTimerScale.
func WGTimerScale() (int, error) {
	v := os.Getenv(WGTimerScaleEnv)
	if v == "" {
		return DefaultWGTimerScale, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxWGTimerScale {
		return 0, fmt.Errorf("lab: %s=%q: want a whole number from 1 to %d", WGTimerScaleEnv, v, maxWGTimerScale)
	}
	return n, nil
}

const wireGuardModule = "golang.zx2c4.com/wireguard"

// wgScaledConstants are wireguard-go's device/constants.go timers, divided
// by the scale; wgUnscaledConstants are its counts and sizes, left as
// they are (MaxTimerHandshakes is RekeyAttemptTime / RekeyTimeout written
// out, which scaling both keeps). Every constant of the file is in one of
// the two: a renamed or added one fails the build rather than run with a
// timer the lab didn't scale.
var (
	wgScaledConstants = []string{
		"RekeyAfterTime", "RekeyAttemptTime", "RekeyTimeout", "RekeyTimeoutJitterMaxMs",
		"RejectAfterTime", "KeepaliveTimeout", "CookieRefreshTime", "HandshakeInitationRate",
		"UnderLoadAfterTime",
	}
	wgUnscaledConstants = []string{
		"RekeyAfterMessages", "RejectAfterMessages", "MaxTimerHandshakes", "PaddingMultiple",
		"MinMessageSize", "MaxMessageSize", "MaxContentSize", "MaxPeers",
	}
)

// wgTimerModFile writes into dir a go.mod for the lab's build of thinkpol:
// the checkout's own, with wireguard-go replaced by a copy whose
// device/constants.go has its timers divided by scale, and the go.sum
// go build -modfile reads beside it. It returns the go.mod's path, or ""
// for scale 1. go build -overlay can't do it: it refuses to replace files
// in the module cache. The copy lives in the user's cache, named by its
// content, so the binary built with it (whose build info names the
// replacement's directory) stays the same from run to run.
func wgTimerModFile(ctx context.Context, root, dir string, scale int) (string, error) {
	if scale == 1 {
		return "", nil
	}
	res, err := run(ctx, nil, nil, "go", "-C", root, "mod", "download", "-json", wireGuardModule)
	if err != nil {
		return "", fmt.Errorf("lab: find %s: %w", wireGuardModule, err)
	}
	var mod struct{ Dir, Version string }
	if err := json.Unmarshal([]byte(res.Stdout), &mod); err != nil || mod.Dir == "" || mod.Version == "" {
		return "", fmt.Errorf("lab: find %s: no directory or version in %q", wireGuardModule, res.Stdout)
	}
	orig := filepath.Join(mod.Dir, "device", "constants.go")
	src, err := os.ReadFile(orig)
	if err != nil {
		return "", fmt.Errorf("lab: %w", err)
	}
	scaled, err := scaleWGConstants(src, scale)
	if err != nil {
		return "", fmt.Errorf("lab: scale %s's timers in %s: %w", wireGuardModule, orig, err)
	}
	copyDir, err := scaledWireGuardCopy(mod.Dir, mod.Version, scaled)
	if err != nil {
		return "", fmt.Errorf("lab: copy %s with its timers scaled: %w", wireGuardModule, err)
	}
	if err := noWireGuardReplace(ctx, root); err != nil {
		return "", err
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	gomod = fmt.Appendf(gomod, "\nreplace %s => %s\n", wireGuardModule, copyDir)
	gosum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return "", err
	}
	modfile := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modfile, gomod, 0o644); err != nil {
		return "", err
	}
	return modfile, os.WriteFile(filepath.Join(dir, "go.sum"), gosum, 0o644)
}

// noWireGuardReplace fails when the checkout's go.mod replaces
// wireguard-go itself: the lab's replace would fight it.
func noWireGuardReplace(ctx context.Context, root string) error {
	res, err := run(ctx, nil, nil, "go", "-C", root, "mod", "edit", "-json")
	if err != nil {
		return fmt.Errorf("lab: read go.mod: %w", err)
	}
	var mod struct {
		Replace []struct{ Old struct{ Path string } }
	}
	if err := json.Unmarshal([]byte(res.Stdout), &mod); err != nil {
		return fmt.Errorf("lab: read go.mod: %w", err)
	}
	for _, r := range mod.Replace {
		if r.Old.Path == wireGuardModule {
			return fmt.Errorf("lab: go.mod replaces %s already: the lab can't scale its timers", wireGuardModule)
		}
	}
	return nil
}

// scaledWireGuardCopy copies the module in modDir, with constants in place
// of its device/constants.go, to a directory of the user's cache named by
// the version and the constants, unless it is there already with the
// same content, and returns that directory. A copy whose content differs
// (edited, or broken) is made again, and copies a killed build left
// unfinished are removed.
func scaledWireGuardCopy(modDir, version string, constants []byte) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(constants)
	parent := filepath.Join(cache, "thinkpol-lab", "wgtimers")
	dst := filepath.Join(parent, version+"-"+hex.EncodeToString(sum[:6]))
	want, err := wgTreeHash(os.DirFS(modDir), constants)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dst, "go.mod")); err == nil {
		if got, err := wgTreeHash(os.DirFS(dst), nil); err == nil && got == want {
			return dst, nil
		}
		if err := os.RemoveAll(dst); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	removeStaleCopies(parent)
	tmp, err := os.MkdirTemp(parent, wgCopyPrefix)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.CopyFS(tmp, os.DirFS(modDir)); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(tmp, "device", "constants.go"), constants, 0o644); err != nil {
		return "", err
	}
	// Another process may have made the same copy meanwhile: either is
	// the same content.
	if err := os.Rename(tmp, dst); err != nil {
		if got, herr := wgTreeHash(os.DirFS(dst), nil); herr != nil || got != want {
			return "", err
		}
	}
	return dst, nil
}

// wgCopyPrefix names a copy still being made.
const wgCopyPrefix = ".copy-"

// removeStaleCopies removes the copies in parent a build left unfinished
// (killed before it renamed its copy) over an hour ago: a running build
// makes its copy in seconds.
func removeStaleCopies(parent string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), wgCopyPrefix) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
			_ = os.RemoveAll(filepath.Join(parent, e.Name()))
		}
	}
}

// wgTreeHash hashes every file of fsys, its path and its content, with
// constants (if not nil) in place of device/constants.go's.
func wgTreeHash(fsys fs.FS, constants []byte) (string, error) {
	h := sha256.New()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		if constants != nil && path == "device/constants.go" {
			b = constants
		}
		// A hash's Write never fails.
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", path, len(b))
		_, _ = h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}

// scaleWGConstants rewrites wireguard-go's device/constants.go with every
// constant of wgScaledConstants divided by scale, the rest of the file
// byte for byte. A constant of the file in neither list, or one of the
// lists missing from it, is an error.
func scaleWGConstants(src []byte, scale int) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "constants.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	if f.Name.Name != "device" {
		return nil, fmt.Errorf("package %s, want device", f.Name.Name)
	}
	type span struct{ start, end int }
	var spans []span
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			vs := spec.(*ast.ValueSpec)
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				return nil, fmt.Errorf("a const spec at %s isn't one name = one value", fset.Position(vs.Pos()))
			}
			name := vs.Names[0].Name
			if seen[name] {
				return nil, fmt.Errorf("constant %s twice", name)
			}
			seen[name] = true
			switch {
			case slices.Contains(wgScaledConstants, name):
				v := vs.Values[0]
				spans = append(spans, span{fset.Position(v.Pos()).Offset, fset.Position(v.End()).Offset})
			case !slices.Contains(wgUnscaledConstants, name):
				return nil, fmt.Errorf("constant %s: not known to the lab as a timer or a count", name)
			}
		}
	}
	var missing []string
	for _, name := range slices.Concat(wgScaledConstants, wgUnscaledConstants) {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("constants missing: %s", strings.Join(missing, ", "))
	}
	var b bytes.Buffer
	at := 0
	for _, s := range spans {
		fmt.Fprintf(&b, "%s(%s) / %d", src[at:s.start], src[s.start:s.end], scale)
		at = s.end
	}
	b.Write(src[at:])
	return b.Bytes(), nil
}
