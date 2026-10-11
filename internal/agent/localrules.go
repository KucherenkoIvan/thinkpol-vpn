package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// LocalRulesFile, in a device's state directory, is the device's own
// routing choice (DESIGN.md "Routing rules and DNS"): the preset its rules
// start from and its own rules ahead of it, in the rule engine's text form
// (TP-015's rules.Local). Only the service writes it, when the local API
// asks (SetRulePreset); it is read like the node's other files, owned by
// the node's user and writable by nobody else.
const LocalRulesFile = "rules.local"

// localRulesLimit bounds the file.
const localRulesLimit = 64 << 10

// maxLocalRules bounds the device's own rules (as rules.Local does).
const maxLocalRules = 1024

// RulePresets are the presets' names: the space's own rules (the default),
// everything through the tunnel, everything but the domestic list.
var RulePresets = []string{"space", "everything", "all-but-domestic"}

// ErrUnknownPreset is a preset name not in RulePresets.
var ErrUnknownPreset = errors.New("agent: no such rule preset")

// ErrPresetUnavailable is a preset the space can't build (no exit, or no
// domestic list): the rule engine's rules.ErrPresetUnavailable.
var ErrPresetUnavailable = errors.New("agent: the space can't build that preset")

// LocalRules is what LocalRulesFile holds.
type LocalRules struct {
	// Preset is one of RulePresets; empty is "space".
	Preset string
	// Rules are the device's own rules, one per line as the rule engine
	// reads them, in order.
	Rules []string
}

// PresetName is the preset, "space" for none.
func (l LocalRules) PresetName() string {
	if l.Preset == "" {
		return RulePresets[0]
	}
	return l.Preset
}

// MarshalText writes the file: a `preset <name>` line (left out for the
// space's rules), then one rule per line.
func (l LocalRules) MarshalText() ([]byte, error) {
	var b bytes.Buffer
	if p := l.PresetName(); p != RulePresets[0] {
		if !slices.Contains(RulePresets, p) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, p)
		}
		fmt.Fprintf(&b, "preset %s\n", p)
	}
	for _, r := range l.Rules {
		fmt.Fprintln(&b, r)
	}
	return b.Bytes(), nil
}

// ParseLocalRules reads the file: blank lines and lines starting with `#`
// are ignored, at most one `preset <name>` line, every other line a rule.
// The rules are checked by the rule engine when it takes them (TP-015
// replaces this with rules.Local's parser).
func ParseLocalRules(text []byte) (LocalRules, error) {
	var out LocalRules
	sawPreset := false
	sc := bufio.NewScanner(bytes.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, ok := strings.CutPrefix(line, "preset "); ok {
			name = strings.TrimSpace(name)
			if !slices.Contains(RulePresets, name) {
				return LocalRules{}, fmt.Errorf("line %d: %w: %q", n, ErrUnknownPreset, name)
			}
			if sawPreset {
				return LocalRules{}, fmt.Errorf("line %d: a second preset", n)
			}
			out.Preset, sawPreset = name, true
			continue
		}
		if len(out.Rules) == maxLocalRules {
			return LocalRules{}, fmt.Errorf("line %d: more than %d rules", n, maxLocalRules)
		}
		out.Rules = append(out.Rules, line)
	}
	if err := sc.Err(); err != nil {
		return LocalRules{}, err
	}
	if out.Preset == RulePresets[0] {
		out.Preset = ""
	}
	return out, nil
}
