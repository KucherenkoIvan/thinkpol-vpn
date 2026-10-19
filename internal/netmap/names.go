package netmap

import (
	"errors"
	"fmt"
)

// maxLabel is a DNS label's longest form.
const maxLabel = 63

// checkName is the shape behind CheckLabel, CheckListName and
// CheckChainName: 1-maxLen lowercase letters, digits and dashes, a letter
// or digit first. dashLast says the name may also end with a dash (a
// list's or a chain's may, a DNS label may not).
func checkName(name string, maxLen int, dashLast bool) bool {
	if name == "" || len(name) > maxLen || name[0] == '-' || !dashLast && name[len(name)-1] == '-' {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// CheckLabel reports whether name can be a node's or a space's overlay
// name: one DNS label of 1-63 lowercase letters, digits and dashes, with
// no dash at either end.
func CheckLabel(name string) error {
	if checkName(name, maxLabel, false) {
		return nil
	}
	return fmt.Errorf("name %q: use 1-%d lowercase letters, digits and dashes, starting and ending with a letter or digit", name, maxLabel)
}

// validateNames is Build's check of the overlay names: only a device's
// section has them (a server's holds no member names), each is a DNS
// label, there is a space name for them to live in, and no two nodes of
// the section share one. Readers don't check: the resolver ignores a name
// it can't serve.
func (s *Section) validateNames() error {
	named := s.SpaceName != "" || s.Node.Name != ""
	for _, p := range s.Peers {
		named = named || p.Name != ""
	}
	if !named {
		return nil
	}
	if s.Node.Kind != NodeDevice {
		return errors.New("names: only devices' sections hold names")
	}
	if s.SpaceName == "" {
		return errors.New("names: no space name for them")
	}
	if err := CheckLabel(s.SpaceName); err != nil {
		return fmt.Errorf("space %w", err)
	}
	taken := make(map[string]bool, len(s.Peers)+1)
	check := func(name string) error {
		if name == "" {
			return nil
		}
		if err := CheckLabel(name); err != nil {
			return err
		}
		if taken[name] {
			return fmt.Errorf("name %q taken twice", name)
		}
		taken[name] = true
		return nil
	}
	if err := check(s.Node.Name); err != nil {
		return fmt.Errorf("node %w", err)
	}
	for _, p := range s.Peers {
		if err := check(p.Name); err != nil {
			return fmt.Errorf("peer %v: %w", p.ID, err)
		}
	}
	return nil
}
