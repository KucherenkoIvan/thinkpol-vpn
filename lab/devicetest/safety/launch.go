//go:build darwin || linux

package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
)

// launchScript is the one command sudo runs. It ignores the terminal's
// signals, Ctrl-\'s QUIT included (neither a closed window nor a key can
// stop it between the copy and the exec). The root copy keeps only HUP
// and INT ignored: Go installs its own QUIT and TERM handlers at start,
// so until the root mode's signal.Ignore runs (after its flags are
// parsed) a Ctrl-\ or a TERM can kill it, leaving its tpdt.* directory,
// with no journal yet, until the next reboot. It checks the temporary
// directory is root's and sticky (not a symlink: find doesn't follow
// one), copies the binary into a fresh directory of root's (0700) there,
// checks the copy's hash against the one the user side computed before
// asking for sudo, and runs the copy: a file the user can write is never
// executed as root, and a binary swapped between the hash and the copy is
// refused.
const launchScript = `set -eu
trap '' HUP INT TERM QUIT
src=$1; sum=$2; base=$3; hasher=$4; shift 4
umask 077
if [ "$(/usr/bin/find "$base" -maxdepth 0 -type d -user root -perm -1000)" != "$base" ]; then
	echo "devicetest: $base is not a sticky directory of root's: refused" >&2
	exit 1
fi
d=$(/usr/bin/mktemp -d "$base/tpdt.XXXXXX")
/bin/cp -- "$src" "$d/devicetest"
/bin/chmod 0500 "$d/devicetest"
got=$($hasher "$d/devicetest" | { read -r h _; echo "$h"; })
if [ "$got" != "$sum" ]; then
	/bin/rm -f "$d/devicetest"; /bin/rmdir "$d"
	echo "devicetest: the root copy's hash is not the binary's: refused" >&2
	exit 1
fi
exec "$d/devicetest" "$@" -root-copy "$d"
`

// RootCommand builds the command that runs a root mode of the root binary
// at self (args: a mode, then its flags) through the launch script: under
// sudo, or directly when the caller is root already (the lab).
func RootCommand(self string, args []string) (*exec.Cmd, error) {
	sum, err := fileSHA256(self)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"/bin/sh", "-c", launchScript, "devicetest-launch", self, sum, rootCopyBase, hasher}, args...)
	if os.Geteuid() != 0 {
		argv = append([]string{"/usr/bin/sudo"}, argv...)
	}
	return exec.Command(argv[0], argv[1:]...), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var rootCopyDir = regexp.MustCompile(`^` + regexp.QuoteMeta(rootCopyBase) + `/tpdt\.[A-Za-z0-9]{6,}$`)

// checkRootCopy checks that this process runs from the launch script's
// copy in dir: dir is one mktemp made, root's and 0700, and the binary in
// it is root's and writable by no one else.
func checkRootCopy(dir string) error {
	if err := checkRootCopyDir(dir); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	want, err := filepath.EvalSymlinks(filepath.Join(dir, "devicetest"))
	if err != nil || exe != want {
		return fmt.Errorf("running %s, not the root copy in %s", exe, dir)
	}
	fi, err := os.Lstat(want)
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: not a file only root may write", want)
	}
	return nil
}

func checkRootCopyDir(dir string) error {
	if !rootCopyDir.MatchString(dir) {
		return fmt.Errorf("%q is not a root copy's directory", dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || int(st.Uid) != os.Geteuid() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s: not a 0700 directory of root's", dir)
	}
	return nil
}

// removeRootCopy deletes the root copy: the binary, then its directory,
// nothing else ("" is none; a missing directory is gone already).
func removeRootCopy(dir string) error {
	if dir == "" {
		return nil
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil // gone already (a reboot empties the temporary directory)
	}
	if err := checkRootCopyDir(dir); err != nil {
		return err
	}
	bin := filepath.Join(dir, "devicetest")
	if fi, err := os.Lstat(bin); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file: left", bin)
	}
	if err := os.Remove(bin); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(dir)
}
