package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// DeviceFile, in the state directory next to NodeFile, is the member's
// toggles on this device (docs/design/configuration.md "Device level"):
// JSON, 0600, written only by the service, when a member of the API group
// changes a toggle through the local API, and by nothing else. It is read
// like the node's other files, and one that can't be read or parsed stops
// the node from starting rather than reading as none. None is every
// toggle at its default.
const DeviceFile = "device.json"

// LocalRulesFile is where a device kept its rules before DeviceFile: the
// first start that finds it carries it into DeviceFile and removes it
// (Node.Adapters).
const LocalRulesFile = "rules.local"

// deviceFileLimit bounds DeviceFile, and LocalRulesFile.
const deviceFileLimit = 256 << 10

// DeviceSettings are a member's toggles on a device.
type DeviceSettings struct {
	// ConnectOnBoot: the service connects the device at a boot's first
	// start (PRD D5: off unless the member turns it on).
	ConnectOnBoot bool
	// Rules are the device's routing choice (docs/design/routing.md
	// "Routing rules and DNS"): the preset its rules start from and its
	// own rules ahead of it.
	Rules rules.Local
	// KillSwitch and AllowLAN are the kill switch's toggles, nil until a
	// member set them: the node's defaults hold until then
	// (Config.KillSwitch, Config.AllowLAN).
	KillSwitch, AllowLAN *bool
}

// deviceSettingsJSON is DeviceFile's keys. A key left out is its default;
// the service writes every key, but the kill switch's until a member set
// them (the node's defaults hold until then).
type deviceSettingsJSON struct {
	ConnectOnBoot *bool     `json:"connect_on_boot"`
	RulePreset    *string   `json:"rule_preset"`
	Rules         *[]string `json:"rules"`
	KillSwitch    *bool     `json:"kill_switch,omitempty"`
	AllowLAN      *bool     `json:"allow_lan,omitempty"`
}

// parseDeviceSettings reads DeviceFile.
func parseDeviceSettings(data []byte) (DeviceSettings, error) {
	var j deviceSettingsJSON
	var s DeviceSettings
	if err := decodeSettings(data, &j); err != nil {
		return s, err
	}
	if j.ConnectOnBoot != nil {
		s.ConnectOnBoot = *j.ConnectOnBoot
	}
	s.KillSwitch, s.AllowLAN = j.KillSwitch, j.AllowLAN
	if j.RulePreset != nil {
		p, err := rules.ParsePreset(*j.RulePreset)
		if err != nil {
			return s, fmt.Errorf("key %q: %w", "rule_preset", err)
		}
		s.Rules.Preset = p
	}
	if j.Rules != nil {
		if len(*j.Rules) > rules.MaxLocalRules {
			return s, fmt.Errorf("key %q: more than %d rules", "rules", rules.MaxLocalRules)
		}
		for i, line := range *j.Rules {
			r, err := netmap.ParseRule(line)
			if err != nil {
				return s, fmt.Errorf("key %q, rule %d: %w", "rules", i+1, err)
			}
			s.Rules.Rules = append(s.Rules.Rules, r)
		}
	}
	return s, nil
}

// marshal is DeviceFile's contents, every key written.
func (s DeviceSettings) marshal() ([]byte, error) {
	preset := s.Rules.Preset.String()
	if _, err := rules.ParsePreset(preset); err != nil {
		return nil, err
	}
	own := make([]string, 0, len(s.Rules.Rules))
	for _, r := range s.Rules.Rules {
		if err := r.Check(); err != nil {
			return nil, err
		}
		own = append(own, r.String())
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// A rule reads "match -> action": keep its ">" as is.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(deviceSettingsJSON{ConnectOnBoot: &s.ConnectOnBoot, RulePreset: &preset, Rules: &own, KillSwitch: s.KillSwitch, AllowLAN: s.AllowLAN}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ErrUnknownPreset is a preset name rules.ParsePreset doesn't know.
var ErrUnknownPreset = errors.New("agent: no such rule preset")

// ErrPresetUnavailable is a preset the space's map can't build (no chain,
// or no domestic list): the choice is kept and enforced failing closed.
var ErrPresetUnavailable = rules.ErrPresetUnavailable

// ErrPresetNotEnforced is a preset stored and shown, whose routes the
// data plane failed to lay out: the router keeps the previous rules until
// a retry lays them out (Status: RulesEnforced unset while connected,
// ProblemPresetNotEnforced).
var ErrPresetNotEnforced = errors.New("agent: rule preset stored, but not enforced yet")

// parseLocalRules reads LocalRulesFile.
func parseLocalRules(text []byte) (rules.Local, error) {
	var l rules.Local
	err := l.UnmarshalText(text)
	return l, err
}
