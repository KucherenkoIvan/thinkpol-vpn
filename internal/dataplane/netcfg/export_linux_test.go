//go:build linux && !android

package netcfg

import "errors"

// failingClose is a real configurator whose Close fails before doing
// anything.
type failingClose struct{ *linuxConfigurator }

func (failingClose) Close() error { return errors.New("netlink gone") }

// ClearFailingClose clears owner in the namespace at path with a Close
// that fails.
func ClearFailingClose(path string, owner Owner) error {
	return ClearWith(func() (Configurator, error) {
		c, err := NewInNamespace(path, owner)
		if err != nil {
			return nil, err
		}
		return failingClose{c.(*linuxConfigurator)}, nil
	}, nil)
}
