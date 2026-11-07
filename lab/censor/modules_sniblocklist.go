package censor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func init() {
	RegisterPassive("sni-blocklist", newSNIBlocklist)
}

// sniBlocklist is a censor's name blocklist: a TCP connection whose
// ClientHello asks for a listed name, or a name under one, is blocked
// (reset by default, as censors that read the name do). It reads the
// ClientHello from the stream, so one split over segments, sent out of
// order, or split over TLS records is read whole; until all of it has
// arrived its packets pass, and the packet that completes it meets the
// verdict. A stream that starts with anything else, joined midstream, or
// whose ClientHello outgrows the stream's prefix, is not judged: the
// module retires from it. A ClientHello without a server name passes,
// and so does an encrypted one (ECH): it reads the outer name only.
type sniBlocklist struct {
	names map[string]bool
	block blocking
}

// newSNIBlocklist builds the module from its settings:
//
//	{"names": ["example.net"], "verdict": "reset"}
//
// with blockSettings' verdict (reset by default), rate and burst. Names
// are compared without case or a trailing dot.
func newSNIBlocklist(settings json.RawMessage) (Passive, error) {
	var s struct {
		Names []string `json:"names"`
		blockSettings
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	m := &sniBlocklist{names: map[string]bool{}}
	for _, n := range s.Names {
		n = canonicalName(n)
		if n == "" || strings.Contains(n, "..") {
			return nil, fmt.Errorf("name %q", n)
		}
		m.names[n] = true
	}
	if len(m.names) == 0 {
		return nil, fmt.Errorf("no names")
	}
	var err error
	if m.block, err = s.blockSettings.parse(Reset); err != nil {
		return nil, err
	}
	return m, nil
}

func canonicalName(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

func (m *sniBlocklist) Name() string { return "sni-blocklist" }

func (m *sniBlocklist) Inspect(_ *Packet, f *Flow) Decision {
	if f.Stream == nil || f.Stream.Midstream() {
		return retire
	}
	prefix := f.Stream.Prefix()
	if len(prefix) == 0 {
		return Decision{Verdict: Accept}
	}
	name, err := clientHelloServerName(prefix)
	switch {
	case errors.Is(err, errIncomplete) && len(prefix) < retainBytes:
		return Decision{Verdict: Accept}
	case err != nil:
		return retire
	}
	if listed, ok := m.listed(name); ok {
		return m.block.decide(fmt.Sprintf("server name %s listed as %s", name, listed))
	}
	return retire
}

// listed finds the listed name that name is, or is under.
func (m *sniBlocklist) listed(name string) (string, bool) {
	name = canonicalName(name)
	for name != "" {
		if m.names[name] {
			return name, true
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return "", false
}
