package rules

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Preset is the base a device's own rules go on top of.
type Preset uint8

const (
	// PresetSpace is the space's default rules, as the map has them.
	PresetSpace Preset = iota
	// PresetEverything sends everything but the local ranges through the
	// presets' chain.
	PresetEverything
	// PresetAllButDomestic also keeps the presets' domestic GeoIP list out
	// of the tunnel.
	PresetAllButDomestic
)

var presetNames = [...]string{PresetSpace: "space", PresetEverything: "everything", PresetAllButDomestic: "all-but-domestic"}

func (p Preset) String() string {
	if int(p) < len(presetNames) {
		return presetNames[p]
	}
	return fmt.Sprintf("Preset(%d)", uint8(p))
}

// ParsePreset reads a preset's name: space, everything or
// all-but-domestic.
func ParsePreset(s string) (Preset, error) {
	if i := slices.Index(presetNames[:], s); i >= 0 {
		return Preset(i), nil
	}
	return 0, fmt.Errorf("rules: preset %q: want one of %s", s, strings.Join(presetNames[:], ", "))
}

// ErrPresetUnavailable is a preset the map's preset settings can't build:
// no chain, or for "all but domestic" no domestic list.
var ErrPresetUnavailable = errors.New("rules: preset unavailable in this space")

// PresetRules returns a preset's rules: for PresetSpace the space's own,
// otherwise built from the map's preset settings.
func PresetRules(p Preset, space []netmap.Rule, s netmap.RulePresets) ([]netmap.Rule, error) {
	local := netmap.Rule{Match: netmap.Match{Kind: netmap.MatchLocal}, Action: netmap.Direct}
	tunnel := netmap.Rule{Match: netmap.Match{Kind: netmap.MatchDefault}, Action: netmap.ToChain(s.Chain)}
	switch {
	case p == PresetSpace:
		return slices.Clone(space), nil
	case p != PresetEverything && p != PresetAllButDomestic:
		return nil, fmt.Errorf("rules: unknown preset %v", p)
	case s.Chain == "" || p == PresetAllButDomestic && s.Domestic == "":
		return nil, fmt.Errorf("%w: %v", ErrPresetUnavailable, p)
	case p == PresetEverything:
		return []netmap.Rule{local, tunnel}, nil
	}
	domestic := netmap.Rule{Match: netmap.Match{Kind: netmap.MatchGeoIP, Value: s.Domestic}, Action: netmap.Direct}
	return []netmap.Rule{local, domestic, tunnel}, nil
}

// Local is a device's own choice of rules: a preset, and rules that go
// ahead of it. It lives in a local file, never in the map.
type Local struct {
	Preset Preset
	Rules  []netmap.Rule
}

// maxLocalRules bounds the local file.
const maxLocalRules = 1024

// MarshalText writes the local file: a `preset <name>` line (left out for
// PresetSpace), then one rule per line in netmap.ParseRule's form.
func (l Local) MarshalText() ([]byte, error) {
	var b bytes.Buffer
	if int(l.Preset) >= len(presetNames) {
		return nil, fmt.Errorf("rules: unknown preset %v", l.Preset)
	}
	if l.Preset != PresetSpace {
		fmt.Fprintf(&b, "preset %s\n", l.Preset)
	}
	for _, r := range l.Rules {
		if err := r.Check(); err != nil {
			return nil, err
		}
		fmt.Fprintln(&b, r)
	}
	return b.Bytes(), nil
}

// UnmarshalText reads the local file: blank lines and lines starting with
// `#` are ignored; at most one `preset <name>` line; every other line is a
// rule, in order.
func (l *Local) UnmarshalText(text []byte) error {
	var out Local
	sawPreset := false
	sc := bufio.NewScanner(bytes.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, ok := strings.CutPrefix(line, "preset "); ok {
			p, err := ParsePreset(strings.TrimSpace(name))
			if err != nil {
				return fmt.Errorf("line %d: %w", n, err)
			}
			if sawPreset {
				return fmt.Errorf("line %d: a second preset", n)
			}
			out.Preset, sawPreset = p, true
			continue
		}
		r, err := netmap.ParseRule(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		if len(out.Rules) == maxLocalRules {
			return fmt.Errorf("line %d: more than %d rules", n, maxLocalRules)
		}
		out.Rules = append(out.Rules, r)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	*l = out
	return nil
}

// Origin is where an effective rule comes from.
type Origin uint8

const (
	OriginLocal  Origin = iota + 1 // the device's own rules
	OriginSpace                    // the space's default rules, from the map
	OriginPreset                   // a preset built from the map's preset settings
)

func (o Origin) String() string {
	switch o {
	case OriginLocal:
		return "local"
	case OriginSpace:
		return "space"
	case OriginPreset:
		return "preset"
	}
	return fmt.Sprintf("Origin(%d)", uint8(o))
}

// Entry is one rule of a device's effective list.
type Entry struct {
	Rule   netmap.Rule
	Origin Origin
	// Index is the rule's position in its origin's list.
	Index int
}

// Effective is a device's rule list in order: its own rules, then its
// preset's (or the space's). A preset the map can't build falls back to
// the space's rules; base is the one used.
func Effective(space []netmap.Rule, presets netmap.RulePresets, l Local) (entries []Entry, base Preset) {
	for i, r := range l.Rules {
		entries = append(entries, Entry{Rule: r, Origin: OriginLocal, Index: i})
	}
	base, origin := l.Preset, OriginPreset
	baseRules, err := PresetRules(base, space, presets)
	if err != nil || base == PresetSpace {
		base, origin, baseRules = PresetSpace, OriginSpace, space
	}
	for i, r := range baseRules {
		entries = append(entries, Entry{Rule: r, Origin: origin, Index: i})
	}
	return entries, base
}
