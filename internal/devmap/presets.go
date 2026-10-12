package devmap

type rawPresets struct {
	Domestic scalar `yaml:"domestic"`
	Chain    scalar `yaml:"chain"`
}

// presets checks what the presets are built from: the domestic list must
// be a declared list, the chain a declared chain.
func (c *checker) presets(s *Spec, raw *rawSpec, listByName map[string]int) {
	if v := raw.Presets.Domestic; v.set() {
		if name, ok := c.value(v); ok {
			if !hasKey(listByName, name) {
				c.errorf(v.pos, "presets: no list %s (declare it under lists)", name)
			} else {
				s.Presets.Domestic = name
			}
		}
	}
	if v := raw.Presets.Chain; v.set() {
		if name, ok := c.value(v); ok {
			known := false
			for _, ch := range s.Chains {
				known = known || ch.Name == name
			}
			if !known {
				c.errorf(v.pos, "presets: no chain %s (declare it under chains)", name)
			} else {
				s.Presets.Chain = name
			}
		}
	}
}

// presetsNeed is what a device's section needs for the spec's presets:
// the domestic list among the node's lists.
func presetsNeed(s *Spec, n Node) (missingList string) {
	if d := s.Presets.Domestic; d != "" {
		for _, l := range n.Lists {
			if s.Lists[l].Name == d {
				return ""
			}
		}
		return d
	}
	return ""
}
