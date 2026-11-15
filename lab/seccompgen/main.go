// Command seccompgen writes lab/seccomp.json: Docker's default seccomp
// profile, from the moby/profiles/seccomp version this module pins, plus
// one rule that allows pivot_root with CAP_SYS_ADMIN. Run it with
// make lab-seccomp.
//
// It is a module of its own so the main module doesn't depend on
// moby/profiles. It reads the module's default.json instead of calling
// seccomp.DefaultProfile, which builds only for Linux; upstream's tests
// keep the two equal.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/moby/profiles/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const sourceModule = "github.com/moby/profiles/seccomp"

func main() {
	out := flag.String("o", "", "where to write the profile")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "seccompgen:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	if out == "" {
		return errors.New("-o is required")
	}
	list, err := exec.Command("go", "list", "-m", "-json", sourceModule).Output()
	if err != nil {
		return fmt.Errorf("go list %s: %w", sourceModule, err)
	}
	var mod struct{ Dir, Version string }
	if err := json.Unmarshal(list, &mod); err != nil {
		return err
	}
	if mod.Dir == "" {
		return fmt.Errorf("%s %s is not downloaded (go mod download)", sourceModule, mod.Version)
	}
	data, err := os.ReadFile(filepath.Join(mod.Dir, "default.json"))
	if err != nil {
		return err
	}
	profile, err := withPivotRoot(data)
	if err != nil {
		return fmt.Errorf("%s %s: %w", sourceModule, mod.Version, err)
	}
	if err := os.WriteFile(out, profile, 0o644); err != nil {
		return err
	}
	fmt.Printf("seccompgen: wrote %s from %s %s\n", out, sourceModule, mod.Version)
	return nil
}

// withPivotRoot adds the pivot_root rule to the default profile in data.
func withPivotRoot(data []byte) ([]byte, error) {
	var p seccomp.Seccomp
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.DefaultAction != specs.ActErrno {
		return nil, fmt.Errorf("default action %s, want %s", p.DefaultAction, specs.ActErrno)
	}
	for _, s := range p.Syscalls {
		if slices.Contains(s.Names, "pivot_root") {
			return nil, errors.New("the default profile already has a pivot_root rule: the lab's may no longer be needed")
		}
	}
	p.Syscalls = append(p.Syscalls, &seccomp.Syscall{
		LinuxSyscall: specs.LinuxSyscall{Names: []string{"pivot_root"}, Action: specs.ActAllow},
		Includes:     &seccomp.Filter{Caps: []string{"CAP_SYS_ADMIN"}},
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "\t")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
