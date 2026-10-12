package netmap

import (
	"errors"
	"fmt"
)

// maxLabel is a DNS label's longest form.
const maxLabel = 63

// CheckLabel reports whether name can be a node's or a space's overlay
// name: one DNS label of 1-63 lowercase letters, digits and dashes, with
// no dash at either end.
func CheckLabel(name string) error {
	if name == "" || len(name) > maxLabel || name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("name %q: use 1-%d lowercase letters, digits and dashes, no dash at either end", name, maxLabel)
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return fmt.Errorf("name %q: use 1-%d lowercase letters, digits and dashes, no dash at either end", name, maxLabel)
	}
	return nil
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
