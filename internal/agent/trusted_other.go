//go:build !unix

package agent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// trustedDir reads a node's files. Owners and modes aren't checked here:
// there is no data plane on these hosts yet (Windows' is TP-047, which
// brings its ACL checks).
type trustedDir struct {
	f    *os.File
	path string
}

func openTrustedDir(path string) (*trustedDir, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &trustedDir{f: f, path: path}, nil
}

func (d *trustedDir) Close() error { return d.f.Close() }

func (d *trustedDir) names() ([]string, error) { return d.f.Readdirnames(-1) }

func (d *trustedDir) read(name string, _ bool, limit int64) ([]byte, os.FileInfo, error) {
	path := filepath.Join(d.path, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return b, fi, nil
}

func (d *trustedDir) mkdir(name string) error {
	if err := os.Mkdir(filepath.Join(d.path, name), 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (d *trustedDir) writeFile(name string, data []byte) error {
	tmp := filepath.Join(d.path, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(d.path, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (d *trustedDir) remove(name string, _ bool) error { return os.Remove(filepath.Join(d.path, name)) }
