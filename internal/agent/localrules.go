package agent

import (
	"errors"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
)

// LocalRulesFile, in a device's state directory, is the device's own
// routing choice (docs/design/routing.md "Routing rules and DNS"): a rules.Local in its
// text form, the preset its rules start from and its own rules ahead of
// it. Only the service writes it, when the local API asks
// (SetRulePreset); it is read like the node's other files, owned by the
// node's user and writable by nobody else, and one that can't be read or
// parsed stops the node from starting rather than reading as none.
const LocalRulesFile = "rules.local"

// localRulesLimit bounds the file.
const localRulesLimit = 256 << 10

// ErrUnknownPreset is a preset name rules.ParsePreset doesn't know.
var ErrUnknownPreset = errors.New("agent: no such rule preset")

// ErrPresetUnavailable is a preset the space's map can't build (no chain,
// or no domestic list): the choice is kept and enforced failing closed.
var ErrPresetUnavailable = rules.ErrPresetUnavailable

// parseLocalRules reads LocalRulesFile.
func parseLocalRules(text []byte) (rules.Local, error) {
	var l rules.Local
	err := l.UnmarshalText(text)
	return l, err
}
