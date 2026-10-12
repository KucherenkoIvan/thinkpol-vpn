package dns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"SupplementalMatchDomainsNoSearch": true, "ServiceIdentifier": true,
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
type scutil struct{}

const scutilPath = "/usr/sbin/scutil"

func (scutil) run(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, scutilPath)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w: %s", err, bytes.TrimSpace(out))
	}
	return string(out), nil
}

func (s scutil) keys(pattern string) ([]string, error) {
	if err := checkToken(pattern); err != nil {
		return nil, err
	}
	out, err := s.run("list " + pattern + "\n")
	if err != nil {
		return nil, err
	}
	return parseList(out), nil
}

func (s scutil) get(key string) (dict, bool, error) {
	if err := checkToken(key); err != nil {
		return dict{}, false, err
	}
	out, err := s.run("show " + key + "\n")
	if err != nil {
		return dict{}, false, err
	}
	return parseShow(out)
}

func (s scutil) set(key string, d dict) error {
	script, err := setScript(key, d)
	if err != nil {
		return err
	}
	out, err := s.run(script)
	if err != nil {
		return err
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
		return err
	}
	if out = strings.TrimSpace(out); out != "" && !strings.Contains(out, "No such key") {
		return fmt.Errorf("scutil: remove %s: %s", key, out)
	}
	return nil
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
		v := d.strs[k]
		if err := errors.Join(checkToken(k), checkToken(v)); err != nil {
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

// parseList reads `list`'s output: "  subKey [0] = <key>" per key.
func parseList(out string) []string {
	var keys []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "subKey [") {
			continue
		}
		if _, k, ok := strings.Cut(line, "] = "); ok && k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// parseShow reads `show`'s output: a dictionary, or "No such key".
func parseShow(out string) (dict, bool, error) {
	trimmed := strings.TrimSpace(out)
	if strings.Contains(trimmed, "No such key") {
		return dict{}, false, nil
	}
	if !strings.HasPrefix(trimmed, "<dictionary> {") {
		return dict{}, false, fmt.Errorf("scutil: unexpected output %q", firstLine(trimmed))
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
			return dict{}, false, fmt.Errorf("scutil: unexpected line %q", line)
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
	return dict{}, false, errors.New("scutil: unterminated dictionary")
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
