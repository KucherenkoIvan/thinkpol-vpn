// Package evidence is a device-test run's evidence folder, as the user
// side writes it: ~/thinkpol-evidence/<date>-<ticket>/, outside every git
// checkout, with a timestamped transcript of the one terminal the run
// uses. The root side (lab/devicetest/safety) writes its own files into
// the same folder (captures, root reads, snapshots, the journal) and
// hands them to the user. Nothing in the folder is ever deleted by the
// tool: captures are kept.
package evidence

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultBase is where evidence folders go: ~/thinkpol-evidence.
func DefaultBase() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "thinkpol-evidence"), nil
}

// gitCheckout is the git checkout path is in (the nearest directory up
// from it holding .git), "" if none: evidence never goes into one, so it
// can't be committed by accident.
func gitCheckout(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	for dir := abs; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// Folder is one run's evidence folder.
type Folder struct {
	Path string
	out  io.Writer
	mu   sync.Mutex
	log  *os.File
}

// Create makes the folder for a run of ticket started at now:
// <base>/<date>-<ticket>, or -2, -3... after it if that exists. out is
// the terminal.
func Create(base, ticket string, now time.Time, out io.Writer) (*Folder, error) {
	if repo := gitCheckout(base); repo != "" {
		return nil, fmt.Errorf("%s is inside the git checkout %s: evidence never goes into one", base, repo)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	name := now.Format("2006-01-02") + "-" + ticket
	path := filepath.Join(base, name)
	for i := 2; ; i++ {
		err := os.Mkdir(path, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || i > 99 {
			return nil, err
		}
		path = filepath.Join(base, fmt.Sprintf("%s-%d", name, i))
	}
	log, err := os.OpenFile(filepath.Join(path, "harness.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Folder{Path: path, out: out, log: log}, nil
}

// Close closes the transcript.
func (f *Folder) Close() error { return f.log.Close() }

// Logf prints a line to the terminal, after the local time, and to the
// transcript, after the UTC time.
func (f *Folder) Logf(format string, a ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	msg := fmt.Sprintf(format, a...)
	for _, l := range strings.Split(msg, "\n") {
		_, _ = fmt.Fprintf(f.out, "%s %s\n", now.Format("15:04:05"), l)
		_, _ = fmt.Fprintf(f.log, "%s %s\n", now.UTC().Format(time.RFC3339Nano), l)
	}
}

// Ask prints question after the time and reads a line of answer; both go
// into the transcript and notes.md.
func (f *Folder) Ask(in *bufio.Reader, question string) (string, error) {
	f.mu.Lock()
	_, _ = fmt.Fprintf(f.out, "%s %s ", time.Now().Format("15:04:05"), question)
	f.mu.Unlock()
	answer, err := in.ReadString('\n')
	answer = strings.TrimSpace(answer)
	f.Logf("asked: %s answered: %q", question, answer)
	note := fmt.Sprintf("- %s %s: %q\n", time.Now().UTC().Format(time.RFC3339), question, answer)
	if werr := f.appendFile("notes.md", []byte(note)); werr != nil {
		f.Logf("notes.md: %v", werr)
	}
	if err != nil && answer == "" {
		return "", err
	}
	return answer, nil
}

// WriteFile writes rel (its directories made), which must not exist.
func (f *Folder) WriteFile(rel string, data []byte) error {
	path, err := f.path(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return errors.Join(err, w.Close())
}

// WriteJSON writes v, indented, to rel.
func (f *Folder) WriteJSON(rel string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return f.WriteFile(rel, append(b, '\n'))
}

// AppendJSONL appends v as one line to rel.
func (f *Folder) AppendJSONL(rel string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return f.appendFile(rel, append(b, '\n'))
}

func (f *Folder) appendFile(rel string, data []byte) error {
	path, err := f.path(rel)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return errors.Join(err, w.Close())
}

func (f *Folder) path(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", fmt.Errorf("evidence: bad name %q", rel)
	}
	return filepath.Join(f.Path, rel), nil
}
