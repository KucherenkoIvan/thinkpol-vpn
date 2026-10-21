//go:build linux && !android

package netcfg

// ClearFailingClose clears owner in the namespace at path with a real
// Close that fails: the ledger says link's MTU was changed from one the
// kernel refuses to set back.
func ClearFailingClose(path string, owner Owner, link string) error {
	return ClearWith(func() (Configurator, error) {
		c, err := NewInNamespace(path, owner)
		if err != nil {
			return nil, err
		}
		lc := c.(*linuxConfigurator)
		l, err := lc.h.LinkByName(link)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		lc.links.changed[link] = linkChange{index: l.Attrs().Index, origMTU: -1, mtu: l.Attrs().MTU}
		return c, nil
	}, nil)
}
