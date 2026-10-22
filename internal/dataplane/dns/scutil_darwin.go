package dns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// dict is a dynamic store dictionary as scutil shows and sets it: string
// values and arrays of strings. Numbers are written back as numbers for
// the keys known to hold them; anything else scutil can't set (nested
// dictionaries, data) makes a dict opaque.
type dict struct {
	strs   map[string]string
	arrays map[string][]string
	opaque bool
}

func newDict() dict { return dict{strs: map[string]string{}, arrays: map[string][]string{}} }

func (d dict) array(key string) []string { return d.arrays[key] }

func (d dict) equal(o dict) bool {
	if d.opaque != o.opaque || len(d.strs) != len(o.strs) || len(d.arrays) != len(o.arrays) {
		return false
	}
	for k, v := range d.strs {
		if ov, ok := o.strs[k]; !ok || ov != v {
			return false
		}
	}
	for k, v := range d.arrays {
		if ov, ok := o.arrays[k]; !ok || !slices.Equal(v, ov) {
			return false
		}
	}
	return true
}

// numeric are the DNS keys whose values are numbers.
var numeric = map[string]bool{
	"ServerPort": true, "SearchOrder": true, "SupplementalMatchOrders": true,
	"SupplementalMatchDomainsNoSearch": true, "ServiceIdentifier": true, "ServerTimeout": true,
}

// store is the SystemConfiguration dynamic store, the configuration
// configd keeps in memory per boot (what `scutil` shows).
type store interface {
	// keys lists the keys matching a regular expression.
	keys(pattern string) ([]string, error)
	// get reads a dictionary; false if there is no such key.
	get(key string) (dict, bool, error)
	set(key string, d dict) error
	remove(key string) error
}

// scutil is the store through /usr/sbin/scutil's command language: pure
// Go, no SystemConfiguration framework (cgo) needed.
type scutil struct{ path string }

const scutilPath = "/usr/sbin/scutil"

func (s scutil) run(script string) (string, error) {
	return s.exec(context.Background(), script)
}

// exec runs scutil with args and stdin, bounded at 10 s and by ctx, and
// returns what it printed.
func (s scutil) exec(ctx context.Context, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.path, args...)
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg := bytes.TrimSpace(out); len(msg) > 0 {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return string(out), nil
}

func (s scutil) keys(pattern string) ([]string, error) {
	if err := checkToken(pattern); err != nil {
		return nil, err
	}
	out, err := s.run("list " + pattern + "\n")
	if err != nil {
		return nil, fmt.Errorf("scutil: list %s: %w", pattern, err)
	}
	keys, err := parseList(out)
	if err != nil {
		return nil, fmt.Errorf("scutil: list %s: %w", pattern, err)
	}
	return keys, nil
}

func (s scutil) get(key string) (dict, bool, error) {
	if err := checkToken(key); err != nil {
		return dict{}, false, err
	}
	out, err := s.run("show " + key + "\n")
	if err != nil {
		return dict{}, false, fmt.Errorf("scutil: show %s: %w", key, err)
	}
	d, ok, err := parseShow(out)
	if err != nil {
		return dict{}, false, fmt.Errorf("scutil: show %s: %w", key, err)
	}
	return d, ok, nil
}

func (s scutil) set(key string, d dict) error {
	script, err := setScript(key, d)
	if err != nil {
		return err
	}
	out, err := s.run(script)
	if err != nil {
		return fmt.Errorf("scutil: set %s: %w", key, err)
	}
	// scutil says nothing when every command worked.
	if out = strings.TrimSpace(out); out != "" {
		return fmt.Errorf("scutil: set %s: %s", key, out)
	}
	return nil
}

func (s scutil) remove(key string) error {
	if err := checkToken(key); err != nil {
		return err
	}
	out, err := s.run("remove " + key + "\n")
	if err != nil {
		return fmt.Errorf("scutil: remove %s: %w", key, err)
	}
	if out = strings.TrimSpace(out); out != "" && !strings.Contains(out, "No such key") {
		return fmt.Errorf("scutil: remove %s: %s", key, out)
	}
	return nil
}

// watch subscribes to changes of the store's keys matching patterns
// through a long-lived scutil (`n.add <pattern> pattern`, `n.watch`), which
// prints a notification for every change: each line it prints signals.
// It runs until ctx ends; the channel closes when scutil exits.
func (s scutil) watch(ctx context.Context, patterns []string) (<-chan struct{}, error) {
	var script strings.Builder
	for _, p := range patterns {
		if err := checkToken(p); err != nil {
			return nil, err
		}
		fmt.Fprintf(&script, "n.add %s pattern\n", p)
	}
	script.WriteString("n.watch\n")
	cmd := exec.CommandContext(ctx, s.path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(stdin, script.String()); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		// stdin stays open: scutil keeps watching until ctx kills it.
		defer func() { _ = stdin.Close() }()
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			select {
			case out <- struct{}{}:
			default:
			}
		}
		_ = cmd.Wait()
	}()
	return out, nil
}

// checkToken refuses what scutil's command line would split or misread.
func checkToken(s string) error {
	if s == "" || strings.ContainsAny(s, " \t\r\n\"'\\") {
		return fmt.Errorf("scutil: %q can't be passed as one token", s)
	}
	return nil
}

// setScript is the scutil commands that set key to d.
func setScript(key string, d dict) (string, error) {
	if d.opaque {
		return "", errors.New("scutil: the dictionary holds values scutil can't set")
	}
	if err := checkToken(key); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("d.init\n")
	for _, k := range sortedKeys(d.strs) {
		if err := checkToken(k); err != nil {
			return "", err
		}
		v := d.strs[k]
		if v == "" && !numeric[k] {
			// scutil reads "" as one empty string, as it does in
			// arrays: a value that can't be written back would make
			// the original unrestorable.
			fmt.Fprintf(&b, `d.add %s ""`+"\n", k)
			continue
		}
		if err := checkToken(v); err != nil {
			return "", err
		}
		if numeric[k] {
			fmt.Fprintf(&b, "d.add %s # %s\n", k, v)
		} else {
			fmt.Fprintf(&b, "d.add %s %s\n", k, v)
		}
	}
	for _, k := range sortedKeys(d.arrays) {
		if err := checkToken(k); err != nil {
			return "", err
		}
		kind := "*"
		if numeric[k] {
			kind = "#"
		}
		fmt.Fprintf(&b, "d.add %s %s", k, kind)
		for _, v := range d.arrays[k] {
			if v == "" && !numeric[k] {
				// scutil reads "" as one empty string: an empty
				// supplemental match domain is a default resolver.
				b.WriteString(` ""`)
				continue
			}
			if err := checkToken(v); err != nil {
				return "", err
			}
			b.WriteString(" " + v)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "set %s\n", key)
	return b.String(), nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// parseList reads `list`'s output: "  subKey [0] = <key>" per key, or
// "  no keys." when nothing matches (real scutil always prints it for
// none, so completely empty output is a failed listing). scutil answers
// a command it doesn't know in text and exits 0, so any other line is a
// failed listing, not an empty one.
func parseList(out string) ([]string, error) {
	var keys []string
	sawLine := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case line == "no keys.":
			sawLine = true
		case strings.HasPrefix(line, "subKey ["):
			sawLine = true
			_, k, ok := strings.Cut(line, "] = ")
			if !ok || k == "" {
				return nil, fmt.Errorf("unexpected line %q", line)
			}
			keys = append(keys, k)
		default:
			return nil, fmt.Errorf("unexpected line %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the list: %w", err)
	}
	if !sawLine {
		return nil, errors.New("empty list output")
	}
	return keys, nil
}

// parseShow reads `show`'s output: a dictionary, or "No such key".
func parseShow(out string) (dict, bool, error) {
	trimmed := strings.TrimSpace(out)
	// "No such key" names an absent key; a key whose value contains the
	// phrase is present, so it is matched only outside a dictionary.
	head := trimmed
	if i := strings.Index(trimmed, "<dictionary> {"); i >= 0 {
		head = trimmed[:i]
	}
	if strings.TrimSpace(head) == "No such key" {
		return dict{}, false, nil
	}
	if !strings.HasPrefix(trimmed, "<dictionary> {") {
		return dict{}, false, fmt.Errorf("unexpected output %q", firstLine(trimmed))
	}
	d := newDict()
	lines := strings.Split(trimmed, "\n")[1:]
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "}" {
			return d, true, nil
		}
		k, v, ok := strings.Cut(line, " : ")
		if !ok {
			if k, ok = strings.CutSuffix(line, " :"); ok { // "Key : " trimmed: an empty string value
				d.strs[k] = ""
				continue
			}
			return dict{}, false, fmt.Errorf("unexpected line %q", line)
		}
		switch {
		case v == "<array> {":
			var arr []string
			for i++; i < len(lines); i++ {
				el := strings.TrimSpace(lines[i])
				if el == "}" {
					break
				}
				_, ev, ok := strings.Cut(el, " : ")
				if !ok && strings.HasSuffix(el, " :") { // "0 : " trimmed: an empty string
					arr = append(arr, "")
					continue
				}
				if !ok || strings.HasPrefix(ev, "<") {
					d.opaque = true // nested arrays or dictionaries, data
					if strings.HasSuffix(ev, "{") {
						i = skipBlock(lines, i)
					}
					continue
				}
				arr = append(arr, ev)
			}
			d.arrays[k] = arr
		case strings.HasPrefix(v, "<"):
			d.opaque = true
			if strings.HasSuffix(v, "{") {
				i = skipBlock(lines, i)
			}
		default:
			d.strs[k] = v
		}
	}
	return dict{}, false, errors.New("unterminated dictionary")
}

// skipBlock returns the index of the line closing the block opened at i.
func skipBlock(lines []string, i int) int {
	depth := 1
	for i++; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		switch {
		case strings.HasSuffix(l, "{"):
			depth++
		case l == "}":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return i
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
